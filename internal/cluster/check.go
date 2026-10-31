package cluster

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/report"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

// Scanner checks one image (a whichphp image input such as "registry:php@sha256:...")
// for one platform ("" for the image's default).
type Scanner func(ctx context.Context, input, platform string) (verdict.Report, error)

// Resolver returns the digest a tag points to now.
type Resolver func(ctx context.Context, ref string) (string, error)

// Actions, as for "whichphp image", plus ERROR for an image that couldn't be checked.
const (
	ActionOK      = string(verdict.ActionOK)
	ActionNeeded  = string(verdict.ActionNeeded)
	ActionUnknown = string(verdict.ActionUnknown)
	ActionNoPHP   = string(verdict.ActionNoPHP)
	ActionError   = "ERROR"
)

// rank orders actions from best to worst, for a workload's overall action.
var rank = map[string]int{ActionNoPHP: 0, ActionOK: 1, ActionUnknown: 2, ActionError: 3, ActionNeeded: 4}

// PHP summarizes one PHP build in an image.
type PHP struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	SAPI    string `json:"sapi"`
}

// ImageResult is the verdict for one image digest on one platform.
type ImageResult struct {
	Input          string            `json:"input"`
	Platform       string            `json:"platform,omitempty"`
	Action         string            `json:"action"`
	PHP            []PHP             `json:"php,omitempty"`
	Verdicts       map[string]string `json:"verdicts,omitempty"`
	UploadProgress string            `json:"uploadProgress,omitempty"`
	Created        string            `json:"created,omitempty"`
	// ImageID is the sha256 of the image config, which identifies the content
	// whatever manifest or index digest it was reached through.
	ImageID string `json:"imageID,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ContainerResult is a Container with its verdict and, for a tag, what the tag points
// to now.
type ContainerResult struct {
	Container
	Result ImageResult `json:"result"`
	// RunningUnverified is set when the runtime didn't say which image the pods run,
	// so Result is for the tag as it is now and may not be what the pods run. A fixed
	// result then counts as UNKNOWN; tagNow keeps the tag's own action for the advice.
	RunningUnverified bool `json:"runningUnverified,omitempty"`
	tagNow            string
	// For a tag: the digest it points to now, whether that differs from the running
	// image, and the verdict for the new image when it does.
	TagDigest string       `json:"tagDigest,omitempty"`
	TagMoved  bool         `json:"tagMoved,omitempty"`
	TagResult *ImageResult `json:"tagResult,omitempty"`
	// TagLookupError is set when what the tag points to now couldn't be found out,
	// for example for a private registry.
	TagLookupError string   `json:"tagLookupError,omitempty"`
	Advice         string   `json:"advice,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// Workload groups the containers of one Deployment, StatefulSet, DaemonSet, Job or
// bare pod.
type Workload struct {
	Namespace  string            `json:"namespace"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	Action     string            `json:"action"`
	Redeploy   bool              `json:"redeploy,omitempty"`
	Restart    string            `json:"restart,omitempty"`
	Containers []ContainerResult `json:"containers"`
}

// Result is the whole cluster report.
type Result struct {
	Tool      string     `json:"tool"`
	Version   string     `json:"version"`
	Context   string     `json:"context"`
	Generated string     `json:"generated"`
	Pods      int        `json:"pods"`
	Images    int        `json:"imagesChecked"`
	Action    string     `json:"action"`
	Workloads []Workload `json:"workloads"`
	Notes     []string   `json:"notes,omitempty"`
}

// CheckOptions control a check.
type CheckOptions struct {
	// Context and Kubeconfig are the kubectl context and kubeconfig file (absolute,
	// or "" for kubectl's default), for restart commands. KubeconfigEnv is a
	// KUBECONFIG list of several files, made absolute, for a POSIX shell. NoRestart
	// leaves the commands out, when the kubeconfig can't be named portably.
	Context, Kubeconfig, KubeconfigEnv string
	NoRestart                          bool
	Log                                io.Writer
}

// Check scans every running image once, resolves every tag once, and builds the
// report per workload.
func Check(ctx context.Context, containers []Container, scan Scanner, resolve Resolver, opt CheckOptions) Result {
	logf := func(format string, a ...any) {
		if opt.Log != nil {
			fmt.Fprintf(opt.Log, format+"\n", a...)
		}
	}
	type scanKey struct{ image, platform string }
	scans := map[scanKey]ImageResult{}
	scanned := 0
	doScan := func(input, platform string) ImageResult {
		// The same digest can be named php@sha256:... or docker.io/library/php@sha256:...
		// A failure is kept only under the name that failed: another name for the
		// same digest may be reachable.
		exact := scanKey{input, platform}
		byDigest := exact
		if d := Digest(input); d != "" {
			byDigest.image = d
		}
		// A success for the digest wins over a failure under this name.
		if r, ok := scans[byDigest]; ok {
			return r
		}
		if r, ok := scans[exact]; ok {
			return r
		}
		if strings.IndexFunc(input, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			r := ImageResult{Input: report.Clean(input), Platform: report.Clean(platform), Action: ActionError,
				Error: "the image reference has spaces or control characters, so it wasn't checked"}
			scans[exact] = r
			return r
		}
		scanned++
		logf("[%d] checking %s%s", scanned, report.Clean(input), report.Clean(platformSuffix(platform)))
		rep, err := scan(ctx, input, platform)
		r := summarize(input, platform, rep, err)
		scans[exact] = r
		if r.Action != ActionError {
			scans[byDigest] = r
		}
		return r
	}
	tags := map[string]struct {
		digest string
		err    error
	}{}
	resolveTag := func(image string) (string, error) {
		if t, ok := tags[image]; ok {
			return t.digest, t.err
		}
		d, err := resolve(ctx, image)
		tags[image] = struct {
			digest string
			err    error
		}{d, err}
		return d, err
	}

	byWorkload := map[string]*Workload{}
	pods := map[string]bool{}
	for _, c := range containers {
		for _, p := range c.Pods {
			pods[c.Namespace+"/"+p] = true
		}
		cr := ContainerResult{Container: c}
		switch {
		case c.Running != "":
			cr.Result = doScan("registry:"+c.Running, c.Platform)
		case Digest(c.Image) != "":
			cr.Result = doScan("registry:"+c.Image, c.Platform)
		default:
			// Only the tag is known: check it as it is now, and trust that result for
			// the pods only when the image ID matches what the runtime reported.
			cr.Result = doScan("registry:"+c.Image, c.Platform)
			switch {
			case c.LocalID != "" && c.LocalID == cr.Result.ImageID:
				cr.Notes = append(cr.Notes, "The runtime reported only an image ID; it matches the tag's image now, so that was checked.")
			case cr.Result.Action == ActionError:
				cr.Notes = append(cr.Notes, "The runtime didn't report a registry digest, and the tag couldn't be checked. An image loaded into the nodes rather than pulled from a registry can't be checked here; check it with whichphp image.")
			default:
				cr.RunningUnverified = true
				cr.tagNow = cr.Result.Action
				switch {
				case c.LocalID != "" && cr.Result.ImageID != "":
					cr.Notes = append(cr.Notes, "The runtime reported only an image ID, which isn't the tag's image now, so the tag was checked as it is now; the pods run another image.")
				case c.LocalID != "":
					cr.Notes = append(cr.Notes, "The runtime reported only an image ID, which couldn't be compared with the tag's image, so the tag was checked as it is now; the pods may run another image.")
				default:
					cr.Notes = append(cr.Notes, "The runtime didn't report which image the pods run, so the tag was checked as it is now; the pods may run another image.")
				}
				if cr.Result.Action == ActionOK || cr.Result.Action == ActionNoPHP {
					cr.Result.Action = ActionUnknown
				}
			}
		}

		// What the tag points to now matters only when the running image isn't fine.
		if Tagged(c.Image) && c.Running != "" && cr.Result.Action != ActionOK && cr.Result.Action != ActionNoPHP {
			if d, err := resolveTag(c.Image); err != nil {
				cr.TagLookupError = oneLine(err.Error())
				cr.Notes = append(cr.Notes, "Couldn't look up what the tag points to now: "+cr.TagLookupError)
			} else if d != "" && d != Digest(c.Running) {
				cr.TagDigest = d
				tr := doScan("registry:"+Repository(c.Image)+"@"+d, c.Platform)
				// A tag points to an index whose digest changes when any platform is
				// rebuilt; the image for this platform may be the same.
				if tr.ImageID == "" || tr.ImageID != cr.Result.ImageID {
					cr.TagMoved = true
					cr.TagResult = &tr
				}
			} else {
				cr.TagDigest = d
			}
		}
		cr.Advice = advice(cr)

		key := c.Namespace + "\x00" + c.Kind + "\x00" + c.Workload
		w := byWorkload[key]
		if w == nil {
			w = &Workload{Namespace: c.Namespace, Kind: c.Kind, Name: c.Workload, Action: ActionNoPHP}
			byWorkload[key] = w
		}
		w.Containers = append(w.Containers, cr)
		if rank[cr.Result.Action] > rank[w.Action] {
			w.Action = cr.Result.Action
		}
	}

	res := Result{Tool: "whichphp", Context: opt.Context, Pods: len(pods), Images: scanned, Action: ActionNoPHP}
	noRestartNote := false
	// cmd.exe and PowerShell expand %, $ and ` even inside double quotes, so such a
	// value can't be pasted safely there.
	if windowsShell && strings.ContainsAny(opt.Context+opt.Kubeconfig, "%$`") {
		opt.NoRestart = true
	}
	for _, w := range byWorkload {
		// Redeploying helps only when every container that needs action would get a
		// fixed image from its tag, and nodes pull the tag again.
		needs, fixedByTag := 0, 0
		for _, c := range w.Containers {
			if c.Result.Action == ActionNeeded {
				needs++
				if fixedTag(c) && PullPolicy(c.Container) == "Always" {
					fixedByTag++
				}
			}
		}
		if needs > 0 && needs == fixedByTag {
			w.Redeploy = true
			if !opt.NoRestart {
				w.Restart = restartCommand(opt, *w)
			} else if w.Kind == "Deployment" || w.Kind == "StatefulSet" || w.Kind == "DaemonSet" {
				noRestartNote = true
			}
		}
		res.Workloads = append(res.Workloads, *w)
		if rank[w.Action] > rank[res.Action] {
			res.Action = w.Action
		}
	}
	if noRestartNote {
		res.Notes = append(res.Notes, "The kubeconfig or context can't be named safely in a command for this shell, so the report gives no restart commands: run kubectl rollout restart for the workloads marked for a redeploy, against the same cluster.")
	}
	sort.Slice(res.Workloads, func(i, j int) bool {
		a, b := res.Workloads[i], res.Workloads[j]
		if rank[a.Action] != rank[b.Action] {
			return rank[a.Action] > rank[b.Action]
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	return res
}

func summarize(input, platform string, rep verdict.Report, err error) ImageResult {
	r := ImageResult{Input: input, Platform: platform}
	if err != nil {
		r.Action, r.Error = ActionError, oneLine(err.Error())
		return r
	}
	r.Action = string(rep.Action)
	r.Created = rep.Image.Created
	r.ImageID = rep.Image.ImageID
	if len(rep.Verdicts) > 0 {
		r.Verdicts = map[string]string{}
		for k, v := range rep.Verdicts {
			r.Verdicts[k] = string(v)
		}
	}
	for _, p := range rep.PHP {
		r.PHP = append(r.PHP, PHP{Name: p.Name, Version: p.Version, Source: p.Source, SAPI: p.SAPI})
	}
	if s, ok := rep.Settings[phpini.UploadProgress]; ok {
		r.UploadProgress = s.Effective
	}
	return r
}

// advice says what to do about one container, in a sentence or two.
func advice(c ContainerResult) string {
	if c.RunningUnverified {
		switch c.tagNow {
		case ActionOK, ActionNoPHP:
			what := "fixed"
			if c.tagNow == ActionNoPHP {
				what = "free of PHP"
			}
			a := "The tag's image now is " + what + ", but the pods may run another one. Redeploy so they run the tag's image, with its digest pinned or imagePullPolicy: Always."
			if PullPolicy(c.Container) == "Never" {
				a = "The tag's image now is " + what + ", but the pods may run another one. With imagePullPolicy Never, load the tag's image onto every node, or change the policy, then redeploy."
			}
			return a
		case ActionNeeded:
			return "The tag's image now isn't fixed: rebuild the image on a fixed PHP or move to a fixed tag, then redeploy."
		default:
			return "whichphp couldn't prove the tag's image fixed, and the pods may run another image; check the image the pods run with whichphp image."
		}
	}
	switch c.Result.Action {
	case ActionOK, ActionNoPHP:
		return ""
	case ActionError:
		return "Couldn't check this image: " + c.Result.Error
	case ActionUnknown:
		return "whichphp couldn't prove whether this PHP is fixed; run whichphp image on it to see the evidence."
	}
	switch {
	case fixedTag(c):
		switch p := PullPolicy(c.Container); p {
		case "Always":
			return "The tag now points to a fixed image: redeploy to pick it up."
		case "Never":
			return "The tag now points to a fixed image, but with imagePullPolicy Never the nodes use only images already on them. Pin " +
				Repository(c.Image) + "@" + c.TagDigest + " in the pod spec and load that image onto every node, or set imagePullPolicy: Always, then redeploy."
		default:
			return "The tag now points to a fixed image, but with imagePullPolicy " + p + " nodes that already have the old image keep using it. Pin " +
				Repository(c.Image) + "@" + c.TagDigest + " in the pod spec, or set imagePullPolicy: Always, then redeploy."
		}
	case c.TagResult != nil && c.TagResult.Action == ActionNeeded:
		return "The tag now points to a new image, but that one isn't fixed either: rebuild the image on a fixed PHP or move to a fixed tag."
	case c.TagResult != nil && c.TagResult.Action == ActionUnknown:
		return "The tag now points to a new image, but whichphp couldn't prove that one fixed: run whichphp image on the tag. If it isn't fixed, rebuild the image on a fixed PHP or move to a fixed tag."
	case c.TagResult != nil:
		return "The tag now points to a new image, which couldn't be checked: run whichphp image on the tag. If it isn't fixed, rebuild the image on a fixed PHP or move to a fixed tag."
	case Digest(c.Image) != "":
		return "The pod spec pins this digest: move the pin to a fixed image."
	case c.TagLookupError != "":
		return "What the tag points to now couldn't be checked, so it may already be fixed: run whichphp image on the tag. If it isn't, rebuild the image on a fixed PHP or move to a fixed tag, then redeploy."
	default:
		return "The tag still points to this image: rebuild it on a fixed PHP or move to a fixed tag, then redeploy."
	}
}

// fixedTag reports whether the tag now points to an image that fixes the container.
func fixedTag(c ContainerResult) bool {
	return c.TagResult != nil && (c.TagResult.Action == ActionOK || c.TagResult.Action == ActionNoPHP)
}

// PullPolicy returns the container's imagePullPolicy, or the Kubernetes default
// when the pod spec doesn't say: Always for "latest" or no tag, else IfNotPresent.
func PullPolicy(c Container) string {
	if c.PullPolicy != "" {
		return c.PullPolicy
	}
	if Digest(c.Image) == "" {
		name := c.Image[strings.LastIndex(c.Image, "/")+1:]
		if i := strings.LastIndex(name, ":"); i < 0 || name[i+1:] == "latest" {
			return "Always"
		}
	}
	return "IfNotPresent"
}

// restartCommand names the same kubeconfig and context the check read, so it can't
// reach another cluster that happens to have a context of the same name.
func restartCommand(opt CheckOptions, w Workload) string {
	var args []string
	if opt.Kubeconfig == "" && opt.KubeconfigEnv != "" {
		args = append(args, "KUBECONFIG="+shellQuote(opt.KubeconfigEnv))
	}
	args = append(args, "kubectl")
	if opt.Context != "" {
		args = append(args, "--context", shellQuote(opt.Context))
	}
	if opt.Kubeconfig != "" {
		args = append(args, "--kubeconfig", shellQuote(opt.Kubeconfig))
	}
	switch w.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		args = append(args, "-n", shellQuote(w.Namespace), "rollout", "restart", strings.ToLower(w.Kind)+"/"+shellQuote(w.Name))
		return strings.Join(args, " ")
	}
	return ""
}

// windowsShell makes shellQuote quote for cmd.exe and PowerShell; tests set it.
var windowsShell = runtime.GOOS == "windows"

// shellQuote quotes a value for a copy-and-paste command when it needs it.
// Kubernetes names are DNS labels, so this matters only for context names and
// kubeconfig paths.
func shellQuote(s string) string {
	safeChars := "-_.:/@"
	if windowsShell {
		safeChars += `\`
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(safeChars, r)) {
			safe = false
			break
		}
	}
	if safe && s != "" {
		return s
	}
	if windowsShell {
		// Double quotes work in both cmd.exe and PowerShell for paths with spaces.
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func platformSuffix(p string) string {
	if p == "" {
		return ""
	}
	return " (" + p + ")"
}

// oneLine joins an error onto one line. A long one keeps its start and its end,
// where Syft and the registry put the cause.
func oneLine(s string) string {
	s = strings.ToValidUTF8(strings.Join(strings.Fields(s), " "), "?")
	if len(s) > 600 {
		head, tail := s[:200], s[len(s)-380:]
		for !utf8.ValidString(head) {
			head = head[:len(head)-1]
		}
		for !utf8.ValidString(tail) {
			tail = tail[1:]
		}
		s = head + " … " + tail
	}
	return s
}
