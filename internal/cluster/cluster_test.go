package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/yusufyildiz34/whichphp/internal/phpini"
	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

func d(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// A small cluster: a Deployment on an old digest of a tag that has since been fixed,
// one whose tag is still vulnerable, a digest-pinned pod, a StatefulSet that's fine,
// a sidecar without PHP, an image that can't be scanned, and pods that are skipped.
func podsJSON() []byte {
	type m = map[string]any
	ctrl := true
	podFor := func(ns, name, node, phase string, owner m, labels m, containers []m, statuses []m, init []m, initStatuses []m) m {
		md := m{"namespace": ns, "name": name, "labels": labels}
		if owner != nil {
			owner["controller"] = ctrl
			md["ownerReferences"] = []m{owner}
		}
		return m{"metadata": md, "spec": m{"nodeName": node, "containers": containers, "initContainers": init},
			"status": m{"phase": phase, "containerStatuses": statuses, "initContainerStatuses": initStatuses}}
	}
	items := []m{
		// shop/web: Deployment (via ReplicaSet), 2 pods, running the old digest A of php:8.4-apache.
		podFor("shop", "web-7d9f-abcde", "node-amd", "Running", m{"kind": "ReplicaSet", "name": "web-7d9f"}, m{"pod-template-hash": "7d9f"},
			[]m{{"name": "php", "image": "php:8.4-apache", "imagePullPolicy": "IfNotPresent"}, {"name": "proxy", "image": "nginx:1.27", "imagePullPolicy": "IfNotPresent"}},
			[]m{{"name": "php", "imageID": "docker.io/library/php@" + d('a')}, {"name": "proxy", "imageID": "docker.io/library/nginx@" + d('1')}}, nil, nil),
		podFor("shop", "web-7d9f-fghij", "node-amd", "Running", m{"kind": "ReplicaSet", "name": "web-7d9f"}, m{"pod-template-hash": "7d9f"},
			[]m{{"name": "php", "image": "php:8.4-apache", "imagePullPolicy": "IfNotPresent"}, {"name": "proxy", "image": "nginx:1.27", "imagePullPolicy": "IfNotPresent"}},
			[]m{{"name": "php", "imageID": "docker-pullable://php@" + d('a')}, {"name": "proxy", "imageID": "docker.io/library/nginx@" + d('1')}}, nil, nil),
		// shop/api: another Deployment on digest A, named differently by the runtime,
		// that pulls its tag on every start.
		podFor("shop", "api-66b-aaaaa", "node-amd", "Running", m{"kind": "ReplicaSet", "name": "api-66b"}, m{"pod-template-hash": "66b"},
			[]m{{"name": "php", "image": "php:8.4-apache", "imagePullPolicy": "Always"}},
			[]m{{"name": "php", "imageID": "docker-pullable://php@" + d('a')}}, nil, nil),
		// moved/same: the tag's index digest changed, but this platform's image didn't.
		podFor("moved", "same-1", "node-amd", "Running", m{"kind": "DaemonSet", "name": "same"}, nil,
			[]m{{"name": "s", "image": "php:8.2-fpm", "imagePullPolicy": "Always"}}, []m{{"name": "s", "imageID": "docker.io/library/php@" + d('4')}}, nil, nil),
		// loaded/local-2: only a local image ID, which matches the tag's image now.
		podFor("loaded", "local-2", "node-amd", "Running", nil, nil,
			[]m{{"name": "x", "image": "php:8.3-cli"}}, []m{{"name": "x", "imageID": "docker://" + d('8')}}, nil, nil),
		// legacy/app: Deployment whose tag still points to the vulnerable image L.
		podFor("legacy", "app-55c-xyz", "node-arm", "Running", m{"kind": "ReplicaSet", "name": "app-55c"}, m{"pod-template-hash": "55c"},
			[]m{{"name": "app", "image": "php:8.1-apache", "imagePullPolicy": "Always"}},
			[]m{{"name": "app", "imageID": "docker.io/library/php@" + d('c')}}, nil, nil),
		// pinned: a bare pod pinned to digest P.
		podFor("pinned", "tool", "node-amd", "Running", nil, nil,
			[]m{{"name": "tool", "image": "php@" + d('d')}}, []m{{"name": "tool", "imageID": "docker.io/library/php@" + d('d')}}, nil, nil),
		// data/db: StatefulSet, fixed. Its init container can't be scanned.
		podFor("data", "db-0", "node-amd", "Running", m{"kind": "StatefulSet", "name": "db"}, nil,
			[]m{{"name": "db", "image": "ghcr.io/acme/db:2"}}, []m{{"name": "db", "imageID": "ghcr.io/acme/db@" + d('f')}},
			[]m{{"name": "init", "image": "ghcr.io/acme/broken:1"}}, []m{{"name": "init", "imageID": "ghcr.io/acme/broken@" + d('e')}}),
		// moved/worse: tag moved, but the new image is still vulnerable.
		podFor("moved", "worse-1", "node-amd", "Running", m{"kind": "DaemonSet", "name": "worse"}, nil,
			[]m{{"name": "w", "image": "wordpress:php8.1"}}, []m{{"name": "w", "imageID": "docker.io/library/wordpress@" + d('2')}}, nil, nil),
		// loaded: the runtime reports only a local image ID.
		podFor("loaded", "local-1", "node-amd", "Running", nil, nil,
			[]m{{"name": "x", "image": "php:8.3-cli"}}, []m{{"name": "x", "imageID": "sha256:" + strings.Repeat("9", 64)}}, nil, nil),
		// skipped: system namespace, not running, Windows node.
		podFor("kube-system", "coredns-1", "node-amd", "Running", nil, nil, []m{{"name": "c", "image": "coredns:1"}}, nil, nil, nil),
		podFor("shop", "web-pending", "", "Pending", nil, nil, []m{{"name": "php", "image": "php:8.4-apache"}}, nil, nil, nil),
		podFor("win", "iis", "node-win", "Running", nil, nil, []m{{"name": "iis", "image": "mcr.microsoft.com/windows/servercore/iis"}}, nil, nil, nil),
	}
	b, _ := json.Marshal(m{"items": items})
	return b
}

func nodesJSON() []byte {
	return []byte(`{"items":[
	 {"metadata":{"name":"node-amd"},"status":{"nodeInfo":{"architecture":"amd64","operatingSystem":"linux"}}},
	 {"metadata":{"name":"node-arm"},"status":{"nodeInfo":{"architecture":"arm64","operatingSystem":"linux"}}},
	 {"metadata":{"name":"node-win"},"status":{"nodeInfo":{"architecture":"amd64","operatingSystem":"windows"}}}]}`)
}

func rep(action verdict.Action, version string, v verdict.Verdict) verdict.Report {
	r := verdict.Report{Action: action}
	if version != "" {
		r.PHP = []verdict.PHP{{Name: "php-cli", Version: version, Source: "upstream-build", SAPI: "cli"}}
		r.Verdicts = map[string]verdict.Verdict{"CVE-2026-109618": v, "CVE-2026-109619": v}
		r.Settings = map[string]phpini.Setting{phpini.UploadProgress: {Effective: "on"}}
	}
	return r
}

// fakeScan gives every image an image ID; digests 4 and 5 are the same image reached
// through different indexes, and the tag php:8.3-cli has image ID 888....
func fakeScan(calls *[]string) Scanner {
	return func(ctx context.Context, input, platform string) (verdict.Report, error) {
		*calls = append(*calls, input+"|"+platform)
		r, err := fakeReport(input)
		if err == nil {
			r.Image.ImageID = "id-" + input[len(input)-1:]
			switch {
			case strings.HasSuffix(input, d('4')), strings.HasSuffix(input, d('5')):
				r.Image.ImageID = "id-same"
			case input == "registry:php:8.3-cli":
				r.Image.ImageID = d('8')
			}
		}
		return r, err
	}
}

func fakeReport(input string) (verdict.Report, error) {
	{
		switch {
		case strings.HasSuffix(input, d('a')), strings.HasSuffix(input, d('c')), strings.HasSuffix(input, d('d')), strings.HasSuffix(input, d('2')), strings.HasSuffix(input, d('3')),
			strings.HasSuffix(input, d('4')), strings.HasSuffix(input, d('5')), strings.HasSuffix(input, d('6')):
			return rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable), nil
		case strings.HasSuffix(input, d('b')), strings.HasSuffix(input, d('f')):
			return rep(verdict.ActionOK, "8.4.27", verdict.Fixed), nil
		case strings.HasSuffix(input, d('1')):
			return rep(verdict.ActionNoPHP, "", ""), nil
		case strings.HasSuffix(input, d('e')):
			return verdict.Report{}, errors.New("syft failed:\nmanifest unknown")
		case input == "registry:php:8.3-cli":
			return rep(verdict.ActionOK, "8.3.27", verdict.Fixed), nil
		}
		return verdict.Report{}, errors.New("unexpected input " + input)
	}
}

func fakeResolve(_ context.Context, ref string) (string, error) {
	switch ref {
	case "php:8.4-apache":
		return d('b'), nil // moved from a to b, which is fixed
	case "php:8.1-apache":
		return d('c'), nil // still l
	case "wordpress:php8.1":
		return d('3'), nil // moved, still vulnerable
	case "nginx:1.27":
		return d('1'), nil
	case "ghcr.io/acme/db:2":
		return d('f'), nil
	case "ghcr.io/acme/broken:1":
		return "", errors.New("401 unauthorized")
	case "php:8.2-fpm":
		return d('5'), nil
	}
	return "", errors.New("unexpected ref " + ref)
}

func TestInventory(t *testing.T) {
	cs, notes, err := Inventory(podsJSON(), nodesJSON(), InventoryOptions{SkipNamespaces: SystemNamespaces})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Container{}
	for _, c := range cs {
		got[c.Namespace+"/"+c.Kind+"/"+c.Workload+"/"+c.Name] = c
	}
	web := got["shop/Deployment/web/php"]
	if len(web.Pods) != 2 || Digest(web.Running) != d('a') || web.Platform != "linux/amd64" {
		t.Errorf("web: %+v", web)
	}
	if c := got["legacy/Deployment/app/app"]; c.Platform != "linux/arm64" || c.PullPolicy != "Always" {
		t.Errorf("legacy: %+v", c)
	}
	if c := got["pinned/Pod/tool/tool"]; c.Image != "php@"+d('d') {
		t.Errorf("pinned: %+v", c)
	}
	// An init container's image comes from initContainerStatuses.
	if c := got["data/StatefulSet/db/init"]; !c.Init || c.Running != "ghcr.io/acme/broken@"+d('e') {
		t.Errorf("init container: %+v", c)
	}
	if c := got["loaded/Pod/local-1/x"]; c.Running != "" || c.LocalID != "sha256:"+strings.Repeat("9", 64) {
		t.Errorf("a local image ID must not count as a registry digest: %+v", c)
	}
	if c := got["loaded/Pod/local-2/x"]; c.LocalID != d('8') {
		t.Errorf("docker:// image ID: %+v", c)
	}
	for _, id := range []string{"", "sha256:abc", "docker-pullable://php@" + d('a'), "sha256:" + strings.Repeat("A", 64), "docker://sha512:" + strings.Repeat("a", 128)} {
		if LocalID(id) != "" {
			t.Errorf("LocalID(%q) = %q", id, LocalID(id))
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "kube-system/") || strings.HasPrefix(k, "win/") || strings.Contains(k, "pending") {
			t.Errorf("should be skipped: %s", k)
		}
	}
	joined := strings.Join(notes, " ")
	for _, want := range []string{"Skipped 1 pod in system namespaces.", "Skipped 1 pod not running.", "Skipped 1 pod on Windows nodes."} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes %q lack %q", joined, want)
		}
	}

	// Without node access, platforms are empty and the note says so.
	cs, notes, err = Inventory(podsJSON(), nil, InventoryOptions{})
	if err != nil || len(cs) == 0 || cs[0].Platform != "" || !strings.Contains(strings.Join(notes, " "), "Couldn't list nodes") {
		t.Errorf("no nodes: %v %v %v", cs, notes, err)
	}
	if _, _, err := Inventory([]byte("not json"), nil, InventoryOptions{}); err == nil {
		t.Error("bad pod JSON accepted")
	}
}

func TestRunningRefAndRepository(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io/library/php@" + d('a'):   "docker.io/library/php@" + d('a'),
		"docker-pullable://php@" + d('a'):   "php@" + d('a'),
		"sha256:" + strings.Repeat("9", 64): "",
		"":                                  "",
		"php@sha256:short":                  "",
		"-x@" + d('a'):                      "",
		"localhost:5000/app@" + d('a'):      "localhost:5000/app@" + d('a'),
		"docker://evil;rm -rf /@" + d('a'):  "",
	} {
		if got := RunningRef(in); got != want {
			t.Errorf("RunningRef(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"php:8.4-apache":       "php",
		"localhost:5000/app:1": "localhost:5000/app",
		"localhost:5000/app":   "localhost:5000/app",
		"php:8.4@" + d('a'):    "php",
		"ghcr.io/acme/app":     "ghcr.io/acme/app",
	} {
		if got := Repository(in); got != want {
			t.Errorf("Repository(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	posixShell(t)
	cs, _, err := Inventory(podsJSON(), nodesJSON(), InventoryOptions{SkipNamespaces: SystemNamespaces})
	if err != nil {
		t.Fatal(err)
	}
	var calls, lookups []string
	resolve := func(ctx context.Context, ref string) (string, error) {
		lookups = append(lookups, ref)
		return fakeResolve(ctx, ref)
	}
	res := Check(context.Background(), cs, fakeScan(&calls), resolve, CheckOptions{Context: "kind-lab", Kubeconfig: "/home/me/k3s.yaml"})
	if res.Action != ActionNeeded || res.Pods != 10 {
		t.Fatalf("action %s, pods %d", res.Action, res.Pods)
	}
	// Every distinct image is scanned once, however many pods run it and however
	// the runtime names it.
	seen := map[string]int{}
	for _, c := range calls {
		in, platform, _ := strings.Cut(c, "|")
		k := in
		if Digest(in) != "" {
			k = Digest(in)
		}
		seen[k+"|"+platform]++
		if seen[k+"|"+platform] > 1 {
			t.Errorf("scanned twice: %s", c)
		}
	}
	if res.Images != len(calls) {
		t.Errorf("images %d, scans %d", res.Images, len(calls))
	}
	// Tags are looked up only for images that aren't fine.
	for _, ref := range lookups {
		if ref == "nginx:1.27" || ref == "ghcr.io/acme/db:2" {
			t.Errorf("looked up %s, whose running image is fine", ref)
		}
	}

	wl := map[string]Workload{}
	for _, w := range res.Workloads {
		wl[w.Namespace+"/"+w.Name] = w
	}
	// IfNotPresent: a restart would bring the cached old image back.
	web := wl["shop/web"]
	if web.Redeploy || web.Restart != "" {
		t.Errorf("web with IfNotPresent: redeploy %v, %q", web.Redeploy, web.Restart)
	}
	for _, c := range web.Containers {
		if c.Name == "php" && (!c.TagMoved || c.TagResult == nil || c.TagResult.Action != ActionOK ||
			!strings.Contains(c.Advice, "imagePullPolicy IfNotPresent") || !strings.Contains(c.Advice, "Pin php@"+d('b'))) {
			t.Errorf("web php: %+v", c)
		}
	}
	if api := wl["shop/api"]; !api.Redeploy || api.Restart != "kubectl --context kind-lab --kubeconfig /home/me/k3s.yaml -n shop rollout restart deployment/api" ||
		api.Containers[0].Advice != "The tag now points to a fixed image: redeploy to pick it up." {
		t.Errorf("api: %+v", api)
	}
	if w := wl["legacy/app"]; w.Redeploy || w.Containers[0].TagMoved || !strings.Contains(w.Containers[0].Advice, "still points") {
		t.Errorf("legacy: %+v", w)
	}
	if w := wl["moved/same"]; w.Containers[0].TagMoved || w.Containers[0].TagResult != nil || w.Containers[0].TagDigest != d('5') ||
		!strings.Contains(w.Containers[0].Advice, "still points") {
		t.Errorf("same image behind a new index: %+v", w)
	}
	if w := wl["pinned/tool"]; !strings.Contains(w.Containers[0].Advice, "pins this digest") {
		t.Errorf("pinned: %+v", w)
	}
	if w := wl["moved/worse"]; w.Redeploy || !strings.Contains(w.Containers[0].Advice, "isn't fixed either") {
		t.Errorf("moved: %+v", w)
	}
	if w := wl["data/db"]; w.Action != ActionError {
		t.Errorf("db with an unscannable init container: %s", w.Action)
	}
	// Only a local image ID: the tag's verdict counts only when the IDs match.
	if w := wl["loaded/local-1"]; w.Action != ActionUnknown || !w.Containers[0].RunningUnverified || !strings.Contains(w.Containers[0].Advice, "The tag's image now is fixed, but the pods may run another one") {
		t.Errorf("loaded, unknown image: %+v", w)
	}
	if w := wl["loaded/local-2"]; w.Action != ActionOK || w.Containers[0].RunningUnverified || len(w.Containers[0].Notes) != 1 {
		t.Errorf("loaded, same image ID: %+v", w)
	}
	// Worst first.
	if res.Workloads[0].Action != ActionNeeded || res.Workloads[len(res.Workloads)-1].Action == ActionNeeded {
		t.Errorf("order: %v", res.Workloads)
	}

	// When the tag lookup fails, the advice mustn't claim the tag hasn't moved.
	failing := func(context.Context, string) (string, error) { return "", errors.New("401 unauthorized") }
	res = Check(context.Background(), cs, fakeScan(&calls), failing, CheckOptions{})
	for _, w := range res.Workloads {
		for _, c := range w.Containers {
			if c.Result.Action == ActionNeeded && Tagged(c.Image) && c.Running != "" {
				if c.TagLookupError == "" || strings.Contains(c.Advice, "still points") || !strings.Contains(c.Advice, "couldn't be checked") {
					t.Errorf("%s/%s: advice %q after a failed lookup", w.Name, c.Name, c.Advice)
				}
			}
		}
	}
}

// TestRedeployRules: a redeploy is offered only when every container that needs
// action gets a fixed image from its tag, and the nodes pull the tag again.
func TestRedeployRules(t *testing.T) {
	posixShell(t)
	scan := func(_ context.Context, input, _ string) (verdict.Report, error) {
		switch {
		case strings.HasSuffix(input, d('b')):
			return rep(verdict.ActionOK, "8.4.27", verdict.Fixed), nil
		case strings.HasSuffix(input, d('1')):
			return rep(verdict.ActionNoPHP, "", ""), nil
		case strings.HasSuffix(input, d('7')):
			return rep(verdict.ActionUnknown, "8.4.27", verdict.Unknown), nil
		}
		return rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable), nil
	}
	tags := map[string]string{"fixed:1": d('b'), "fixed": d('b'), "stuck:1": d('c'), "slim:1": d('1'), "unsure:1": d('7')}
	resolve := func(_ context.Context, ref string) (string, error) { return tags[ref], nil }
	mk := func(ns, name, image, policy string, running byte) Container {
		return Container{Namespace: ns, Kind: "Deployment", Workload: "app", Name: name, Image: image, PullPolicy: policy,
			Running: Repository(image) + "@" + d(running), Platform: "linux/amd64", Pods: []string{ns + "-1"}}
	}
	res := Check(context.Background(), []Container{
		mk("mixed", "a", "fixed:1", "Always", 'a'),
		mk("mixed", "b", "stuck:1", "Always", 'c'),
		mk("slim", "a", "slim:1", "Always", '6'),
		mk("never", "a", "fixed:1", "Never", 'a'),
		mk("default", "a", "fixed:1", "", 'a'),
		mk("latest", "a", "fixed", "", 'a'),
		mk("unsure", "a", "unsure:1", "Always", 'a'),
	}, scan, resolve, CheckOptions{Context: "lab"})
	wl := map[string]Workload{}
	for _, w := range res.Workloads {
		wl[w.Namespace] = w
	}
	for ns, want := range map[string]bool{"mixed": false, "slim": true, "never": false, "default": false, "latest": true, "unsure": false} {
		if w := wl[ns]; w.Redeploy != want || (w.Restart != "") != want {
			t.Errorf("%s: redeploy %v, restart %q, want %v", ns, w.Redeploy, w.Restart, want)
		}
	}
	for ns, want := range map[string]string{
		"never":   "with imagePullPolicy Never the nodes use only images already on them. Pin fixed@" + d('b') + " in the pod spec and load that image onto every node",
		"default": "imagePullPolicy IfNotPresent",
		"unsure":  "couldn't prove that one fixed",
		"mixed":   "still points",
	} {
		found := false
		for _, c := range wl[ns].Containers {
			found = found || strings.Contains(c.Advice, want)
		}
		if !found {
			t.Errorf("%s: no advice with %q: %+v", ns, want, wl[ns].Containers)
		}
	}
	for _, tc := range []struct{ image, policy, want string }{
		{"php", "", "Always"}, {"php:latest", "", "Always"}, {"localhost:5000/php", "", "Always"},
		{"localhost:5000/php:8", "", "IfNotPresent"}, {"php@" + d('a'), "", "IfNotPresent"}, {"php:8", "Never", "Never"},
	} {
		if got := PullPolicy(Container{Image: tc.image, PullPolicy: tc.policy}); got != tc.want {
			t.Errorf("PullPolicy(%q, %q) = %s, want %s", tc.image, tc.policy, got, tc.want)
		}
	}
}

// TestHostileText: names, images and messages come from the cluster and registries.
// None of them may start a GitHub Actions workflow command, in the table or in the
// progress lines.
func TestHostileText(t *testing.T) {
	bad := "x\n::warning::pwned ##[group]y"
	r := Result{Context: bad, Action: ActionNeeded, Notes: []string{bad}, Workloads: []Workload{{
		Namespace: bad, Kind: bad, Name: bad, Action: ActionNeeded, Redeploy: true, Restart: bad,
		Containers: []ContainerResult{{
			Container: Container{Name: bad, Image: bad, Platform: bad, Running: "r@" + d('a'), Pods: []string{bad}},
			Result:    ImageResult{Action: ActionNeeded, PHP: []PHP{{Version: bad}}, Verdicts: map[string]string{"c": bad}, Error: bad},
			TagMoved:  true, TagDigest: bad, TagResult: &ImageResult{Action: ActionOK},
			Advice: bad, Notes: []string{bad},
		}, {
			Container: Container{Name: bad, Image: bad, LocalID: bad},
			Result:    ImageResult{Action: ActionOK}, Notes: []string{bad},
		}},
	}, {Namespace: bad, Kind: bad, Name: bad, Action: ActionNoPHP}}}
	var buf bytes.Buffer
	if err := Table(&buf, r); err != nil {
		t.Fatal(err)
	}
	// An image reference with a newline isn't scanned at all, so neither the
	// progress line nor Syft's own output can carry it.
	var log bytes.Buffer
	scans := 0
	scan := func(context.Context, string, string) (verdict.Report, error) {
		scans++
		return verdict.Report{}, errors.New(bad)
	}
	res := Check(context.Background(), []Container{
		{Namespace: "a", Workload: "a", Name: "c", Image: "busybox:1" + bad, Pods: []string{"p"}},
		{Namespace: "b", Workload: "b", Name: "d", Image: "busybox:2", Platform: bad, Pods: []string{"q"}},
	}, scan, func(context.Context, string) (string, error) { return "", errors.New(bad) }, CheckOptions{Log: &log})
	if c := res.Workloads[0].Containers[0]; scans != 1 || c.Name != "c" || c.Result.Action != ActionError {
		t.Errorf("%d scans; hostile image: %+v", scans, c)
	}
	for _, out := range []string{buf.String(), log.String()} {
		if !strings.Contains(out, "pwned") {
			t.Errorf("hostile text missing, so the test checks nothing:\n%s", out)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "::") || strings.Contains(line, "##[") {
				t.Errorf("workflow command: %q", line)
			}
		}
	}
}

func TestTableAndJSON(t *testing.T) {
	posixShell(t)
	cs, _, _ := Inventory(podsJSON(), nodesJSON(), InventoryOptions{SkipNamespaces: SystemNamespaces})
	var calls []string
	scan := fakeScan(&calls)
	hostile := func(ctx context.Context, input, platform string) (verdict.Report, error) {
		r, err := scan(ctx, input, platform)
		if err == nil && len(r.PHP) > 0 {
			r.PHP[0].Version = "8.4.26\n::error::pwned ##[group]x"
		}
		return r, err
	}
	res := Check(context.Background(), cs, hostile, fakeResolve, CheckOptions{Context: "it's-mine"})
	var buf bytes.Buffer
	if err := Table(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Context: it's-mine",
		"ACTION NEEDED  shop/Deployment/web",
		"the tag now points to sha256:bbbbbbbbbbbb…: fixed",
		"Redeploy: kubectl --context 'it'\\''s-mine' -n shop rollout restart deployment/api",
		"OK             loaded/Pod/local-2",
		"running image ID sha256:888888888888…",
		"running image ID sha256:999999999999…, not the tag's image now; checked the tag as it is now",
		"Before you redeploy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "::") || strings.Contains(line, "##[") {
			t.Errorf("workflow command in table: %q", line)
		}
	}
	// Workloads without PHP share one line; the evidence reminder is only for action.
	buf.Reset()
	quiet := Result{Context: "c", Action: ActionNoPHP, Workloads: []Workload{
		{Namespace: "a", Kind: "Deployment", Name: "cache", Action: ActionNoPHP},
		{Namespace: "a", Kind: "Deployment", Name: "api", Action: ActionNoPHP}}}
	if err := Table(&buf, quiet); err != nil || !strings.Contains(buf.String(), "No PHP in 2 workloads: a/Deployment/api, a/Deployment/cache") || strings.Contains(buf.String(), "Before you redeploy") {
		t.Errorf("no-PHP table:\n%s", buf.String())
	}
	buf.Reset()
	if err := JSON(&buf, res); err != nil || !json.Valid(buf.Bytes()) {
		t.Fatalf("JSON: %v", err)
	}
	var back Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || len(back.Workloads) != len(res.Workloads) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	posixShell(t)
	for in, want := range map[string]string{"kind-lab": "kind-lab", "arn:aws:eks:eu-west-1:1:cluster/x": "arn:aws:eks:eu-west-1:1:cluster/x", "a b": "'a b'", "x'y": `'x'\''y'`, "$(id)": "'$(id)'", "": "''"} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzInventory: pod and node lists come from the cluster's API server. Reading them
// must never panic, and every container it returns must have a usable shape.
func FuzzInventory(f *testing.F) {
	f.Add(podsJSON(), nodesJSON())
	f.Add([]byte(`{"items":[{"metadata":{"ownerReferences":[{"kind":"ReplicaSet","name":"-"}],"labels":{"pod-template-hash":""}},"status":{"phase":"Running"},"spec":{"containers":[{}]}}]}`), []byte(`{"items":[{}]}`))
	f.Fuzz(func(t *testing.T, pods, nodes []byte) {
		cs, _, err := Inventory(pods, nodes, InventoryOptions{SkipNamespaces: SystemNamespaces})
		if err != nil {
			return
		}
		for _, c := range cs {
			if len(c.Pods) == 0 {
				t.Fatalf("container without pods: %+v", c)
			}
			if c.Running != "" && Digest(c.Running) == "" {
				t.Fatalf("running %q has no digest", c.Running)
			}
		}
	})
}

func TestOneLineKeepsTheCause(t *testing.T) {
	long := "syft failed: could not determine source:\n " + strings.Repeat("é path/x ", 120) + "\n: no space left on device"
	got := oneLine(long)
	if !strings.HasPrefix(got, "syft failed: could not determine source:") || !strings.HasSuffix(got, "no space left on device") ||
		len(got) > 600 || strings.Contains(got, "\n") || !utf8.ValidString(got) {
		t.Errorf("oneLine: %q", got)
	}
}

// TestLocalImages: when the runtime reports no registry digest, the tag is checked as
// it is now, and the advice says only what that check proved.
func TestLocalImages(t *testing.T) {
	results := map[string]verdict.Report{
		"registry:ok:1":      rep(verdict.ActionOK, "8.4.27", verdict.Fixed),
		"registry:nophp:1":   rep(verdict.ActionNoPHP, "", ""),
		"registry:unsure:1":  rep(verdict.ActionUnknown, "8.4.27", verdict.Unknown),
		"registry:vuln:1":    rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable),
		"registry:noid:1":    rep(verdict.ActionOK, "8.4.27", verdict.Fixed),
		"registry:same:1":    rep(verdict.ActionOK, "8.4.27", verdict.Fixed),
		"registry:private:1": {},
	}
	scan := func(_ context.Context, input, _ string) (verdict.Report, error) {
		r, ok := results[input]
		if !ok || input == "registry:private:1" {
			return verdict.Report{}, errors.New("401 unauthorized")
		}
		if input != "registry:noid:1" {
			r.Image.ImageID = d('8')
		}
		return r, nil
	}
	mk := func(image, local string) Container {
		return Container{Namespace: strings.TrimSuffix(image, ":1"), Kind: "Pod", Workload: "p", Name: "c", Image: image, LocalID: local, Pods: []string{"p"}}
	}
	res := Check(context.Background(), []Container{
		mk("ok:1", d('9')), mk("nophp:1", ""), mk("unsure:1", d('9')), mk("vuln:1", d('9')), mk("noid:1", d('9')), mk("same:1", d('8')), mk("private:1", d('9')),
	}, scan, func(context.Context, string) (string, error) {
		t.Error("no lookup without a running digest")
		return "", nil
	}, CheckOptions{})
	got := map[string]ContainerResult{}
	for _, w := range res.Workloads {
		got[w.Namespace] = w.Containers[0]
	}
	for ns, want := range map[string]struct{ action, advice string }{
		"ok":      {ActionUnknown, "The tag's image now is fixed, but the pods may run another one"},
		"nophp":   {ActionUnknown, "The tag's image now is free of PHP, but the pods may run another one"},
		"unsure":  {ActionUnknown, "couldn't prove the tag's image fixed"},
		"vuln":    {ActionNeeded, "The tag's image now isn't fixed:"},
		"noid":    {ActionUnknown, "The tag's image now is fixed, but the pods may run another one"},
		"same":    {ActionOK, ""},
		"private": {ActionError, "Couldn't check this image"},
	} {
		c := got[ns]
		if c.Result.Action != want.action || !strings.Contains(c.Advice, want.advice) || len(c.Notes) != 1 {
			t.Errorf("%s: %s, %q, notes %q", ns, c.Result.Action, c.Advice, c.Notes)
		}
	}
	if !strings.Contains(got["private"].Notes[0], "loaded into the nodes") || !strings.Contains(got["nophp"].Notes[0], "didn't report which image") ||
		!strings.Contains(got["ok"].Notes[0], "isn't the tag's image now") || !strings.Contains(got["noid"].Notes[0], "couldn't be compared") {
		t.Errorf("notes: %q %q %q %q", got["private"].Notes, got["nophp"].Notes, got["ok"].Notes, got["noid"].Notes)
	}
	// Under imagePullPolicy Never, pinning alone can't help: the image must be on the nodes.
	never := mk("ok:1", d('9'))
	never.Namespace, never.PullPolicy = "never", "Never"
	res = Check(context.Background(), []Container{never}, scan, nil, CheckOptions{})
	if a := res.Workloads[0].Containers[0].Advice; !strings.Contains(a, "load the tag's image onto every node") {
		t.Errorf("Never, unverified: %q", a)
	}
	if id := LocalID(strings.Repeat("a", 64)); id != "sha256:"+strings.Repeat("a", 64) {
		t.Errorf("bare hex image ID: %q", id)
	}
}

// A scan that fails under one name isn't reused for the same digest under another.
func TestFailedScanNotShared(t *testing.T) {
	scan := func(_ context.Context, input, _ string) (verdict.Report, error) {
		if strings.HasPrefix(input, "registry:private.example/") {
			return verdict.Report{}, errors.New("401 unauthorized")
		}
		return rep(verdict.ActionOK, "8.4.27", verdict.Fixed), nil
	}
	mk := func(ns, running string) Container {
		return Container{Namespace: ns, Kind: "Pod", Workload: "p", Name: "c", Image: running, Running: running, Pods: []string{"p"}}
	}
	res := Check(context.Background(), []Container{mk("a", "private.example/php@"+d('a')), mk("b", "php@"+d('a')), mk("c", "docker.io/library/php@"+d('a')),
		mk("d", "private.example/php@"+d('a'))}, scan, fakeResolve, CheckOptions{})
	actions := map[string]string{}
	for _, w := range res.Workloads {
		actions[w.Namespace] = w.Action
	}
	// Once the digest was checked under another name, the failed name gets that result.
	if actions["a"] != ActionError || actions["b"] != ActionOK || actions["c"] != ActionOK || actions["d"] != ActionOK || res.Images != 2 {
		t.Errorf("actions %v, %d scans", actions, res.Images)
	}
}

func TestRestartCommandNamesTheCluster(t *testing.T) {
	posixShell(t)
	w := Workload{Namespace: "shop", Kind: "Deployment", Name: "web"}
	for _, tc := range []struct {
		opt  CheckOptions
		want string
	}{
		{CheckOptions{Context: "lab"}, "kubectl --context lab -n shop rollout restart deployment/web"},
		{CheckOptions{Context: "lab", Kubeconfig: "/home/me/k 1.yaml"}, "kubectl --context lab --kubeconfig '/home/me/k 1.yaml' -n shop rollout restart deployment/web"},
		{CheckOptions{Context: "lab", KubeconfigEnv: "/home/me/a.yaml:/home/me/b.yaml"}, "KUBECONFIG=/home/me/a.yaml:/home/me/b.yaml kubectl --context lab -n shop rollout restart deployment/web"},
		{CheckOptions{Context: "lab", Kubeconfig: "/k", KubeconfigEnv: "/e"}, "kubectl --context lab --kubeconfig /k -n shop rollout restart deployment/web"},
	} {
		if got := restartCommand(tc.opt, w); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

// posixShell makes the restart commands POSIX for one test, whatever the OS.
func posixShell(t *testing.T) {
	old := windowsShell
	windowsShell = false
	t.Cleanup(func() { windowsShell = old })
}

func TestShellQuoteWindows(t *testing.T) {
	old := windowsShell
	windowsShell = true
	defer func() { windowsShell = old }()
	for in, want := range map[string]string{`C:\Users\me\.kube\config`: `C:\Users\me\.kube\config`, `C:\Users\Jane Doe\kc`: `"C:\Users\Jane Doe\kc"`, `a"b`: `"a""b"`} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// When the kubeconfig can't be named portably, the report says so instead of
// giving a command for another cluster.
func TestNoRestartCommand(t *testing.T) {
	scan := func(_ context.Context, input, _ string) (verdict.Report, error) {
		if strings.HasSuffix(input, d('b')) {
			return rep(verdict.ActionOK, "8.4.27", verdict.Fixed), nil
		}
		return rep(verdict.ActionNeeded, "8.4.26", verdict.Vulnerable), nil
	}
	c := Container{Namespace: "shop", Kind: "Deployment", Workload: "web", Name: "php", Image: "php:8.4-apache", PullPolicy: "Always",
		Running: "php@" + d('a'), Pods: []string{"web-1"}}
	res := Check(context.Background(), []Container{c}, scan, func(context.Context, string) (string, error) { return d('b'), nil }, CheckOptions{Context: "lab", NoRestart: true})
	if w := res.Workloads[0]; !w.Redeploy || w.Restart != "" || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "against the same cluster") {
		t.Errorf("workload %+v, notes %q", w, res.Notes)
	}
	// On Windows, a value the shell would expand gets no command either.
	old := windowsShell
	windowsShell = true
	defer func() { windowsShell = old }()
	res = Check(context.Background(), []Container{c}, scan, func(context.Context, string) (string, error) { return d('b'), nil }, CheckOptions{Context: "lab", Kubeconfig: `C:\Users\a$b\kc`})
	if w := res.Workloads[0]; w.Restart != "" || len(res.Notes) != 1 {
		t.Errorf("Windows, $ in the path: workload %+v, notes %q", w, res.Notes)
	}
	res = Check(context.Background(), []Container{c}, scan, func(context.Context, string) (string, error) { return d('b'), nil }, CheckOptions{Context: "lab", Kubeconfig: `C:\Users\me\kc`})
	if w := res.Workloads[0]; w.Restart != `kubectl --context lab --kubeconfig C:\Users\me\kc -n shop rollout restart deployment/web` {
		t.Errorf("Windows: %q", w.Restart)
	}
}
