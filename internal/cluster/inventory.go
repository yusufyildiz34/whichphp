// Package cluster finds the container images a Kubernetes cluster is actually running
// and says which workloads run PHP that isn't fixed for PHP2Shell, and what to do about
// each: redeploy to pick up a fixed image the tag already points to, or rebuild the
// image because the tag itself is still vulnerable.
//
// It only reads: the pod and node lists come from "kubectl get", and images are
// read from their registries. Nothing in the cluster is changed or run.
package cluster

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The subset of the Kubernetes API that whichphp reads.
type podList struct {
	Items []pod `json:"items"`
}

type pod struct {
	Metadata struct {
		Namespace       string            `json:"namespace"`
		Name            string            `json:"name"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []struct {
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			Controller *bool  `json:"controller"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName       string         `json:"nodeName"`
		Containers     []podContainer `json:"containers"`
		InitContainers []podContainer `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		Phase                 string            `json:"phase"`
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type podContainer struct {
	Name            string `json:"name"`
	Image           string `json:"image"`
	ImagePullPolicy string `json:"imagePullPolicy"`
}

type containerStatus struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"imageID"`
}

type nodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			NodeInfo struct {
				Architecture    string `json:"architecture"`
				OperatingSystem string `json:"operatingSystem"`
			} `json:"nodeInfo"`
		} `json:"status"`
	} `json:"items"`
}

// Container is one container image as the cluster runs it: the same workload,
// container name, running image and platform, across all the pods that share them.
type Container struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`     // Deployment, StatefulSet, DaemonSet, Job, ReplicaSet, Pod, ...
	Workload  string `json:"workload"` // its name
	Name      string `json:"container"`
	Init      bool   `json:"init,omitempty"`
	// Image is the reference in the pod spec; Running is repo@sha256:... from the
	// container status, or "" when the runtime didn't report a registry digest.
	Image      string `json:"image"`
	PullPolicy string `json:"pullPolicy,omitempty"`
	Running    string `json:"running,omitempty"`
	// LocalID is the image ID (sha256 of the image config) when the runtime reported
	// only that, for example for an image loaded into the node rather than pulled.
	LocalID  string   `json:"localID,omitempty"`
	Platform string   `json:"platform"`
	Pods     []string `json:"pods"`
}

// SystemNamespaces are skipped unless asked for: they run the cluster's own
// components, which don't ship PHP.
var SystemNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}

// InventoryOptions control which pods count.
type InventoryOptions struct {
	// SkipNamespaces are left out (for example SystemNamespaces).
	SkipNamespaces []string
}

// Inventory reads "kubectl get pods -o json" and "kubectl get nodes -o json" output
// and returns the containers of running pods, merged per workload, container and
// running image. Nodes may be nil when listing them isn't allowed; the platform is
// then empty and the image's default platform is checked. Notes explain anything
// that was skipped.
func Inventory(podsJSON, nodesJSON []byte, opt InventoryOptions) ([]Container, []string, error) {
	var pods podList
	if err := json.Unmarshal(podsJSON, &pods); err != nil {
		return nil, nil, fmt.Errorf("reading the pod list: %w", err)
	}
	platforms := map[string]string{}
	if len(nodesJSON) > 0 {
		var nodes nodeList
		if err := json.Unmarshal(nodesJSON, &nodes); err != nil {
			return nil, nil, fmt.Errorf("reading the node list: %w", err)
		}
		for _, n := range nodes.Items {
			info := n.Status.NodeInfo
			if info.OperatingSystem != "" && info.Architecture != "" {
				platforms[n.Metadata.Name] = info.OperatingSystem + "/" + info.Architecture
			}
		}
	}
	skip := map[string]bool{}
	for _, ns := range opt.SkipNamespaces {
		skip[ns] = true
	}

	var notes []string
	skipped := map[string]int{}
	merged := map[string]*Container{}
	for _, p := range pods.Items {
		md := p.Metadata
		switch {
		case skip[md.Namespace]:
			skipped["in system namespaces"]++
			continue
		case p.Status.Phase != "Running":
			skipped["not running"]++
			continue
		}
		platform := platforms[p.Spec.NodeName]
		if strings.HasPrefix(platform, "windows/") {
			skipped["on Windows nodes"]++
			continue
		}
		kind, workload := owner(p)
		add := func(c podContainer, statuses []containerStatus, init bool) {
			running, local := "", ""
			for _, s := range statuses {
				if s.Name == c.Name {
					running, local = RunningRef(s.ImageID), LocalID(s.ImageID)
				}
			}
			// The same image can be reported as php@sha256:... on one node and
			// docker.io/library/php@sha256:... on another, so merge by digest.
			key := strings.Join([]string{md.Namespace, kind, workload, c.Name, Digest(running), local, c.Image, platform}, "\x00")
			m := merged[key]
			if m == nil {
				m = &Container{Namespace: md.Namespace, Kind: kind, Workload: workload, Name: c.Name, Init: init,
					Image: c.Image, PullPolicy: c.ImagePullPolicy, Running: running, LocalID: local, Platform: platform}
				merged[key] = m
			}
			m.Pods = append(m.Pods, md.Name)
		}
		for _, c := range p.Spec.Containers {
			add(c, p.Status.ContainerStatuses, false)
		}
		for _, c := range p.Spec.InitContainers {
			add(c, p.Status.InitContainerStatuses, true)
		}
	}

	out := make([]Container, 0, len(merged))
	for _, c := range merged {
		sort.Strings(c.Pods)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		for _, cmp := range [][2]string{{a.Namespace, b.Namespace}, {a.Kind, b.Kind}, {a.Workload, b.Workload}, {a.Name, b.Name}, {a.Platform, b.Platform}, {a.Running, b.Running}, {a.LocalID, b.LocalID}, {a.Image, b.Image}} {
			if cmp[0] != cmp[1] {
				return cmp[0] < cmp[1]
			}
		}
		return false
	})
	reasons := make([]string, 0, len(skipped))
	for r := range skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		notes = append(notes, fmt.Sprintf("Skipped %d %s %s.", skipped[r], plural(skipped[r], "pod", "pods"), r))
	}
	if len(nodesJSON) == 0 {
		notes = append(notes, "Couldn't list nodes, so each image was checked for its default platform, and pods on Windows nodes weren't skipped.")
	}
	return out, notes, nil
}

// owner names the workload that controls a pod. A ReplicaSet created by a
// Deployment is reported as the Deployment: its name is the Deployment's plus the
// pod-template-hash label.
func owner(p pod) (kind, name string) {
	for _, o := range p.Metadata.OwnerReferences {
		if o.Controller != nil && !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if h := p.Metadata.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "Deployment", strings.TrimSuffix(o.Name, "-"+h)
			}
		}
		return o.Kind, o.Name
	}
	return "Pod", p.Metadata.Name
}

var digestRefRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}$`)

// RunningRef turns a container status imageID into repo@sha256:..., or "" when the
// runtime reported only a local image ID (for example "sha256:..." for an image that
// was loaded rather than pulled).
func RunningRef(imageID string) string {
	id := imageID
	for _, p := range []string{"docker-pullable://", "docker://"} {
		id = strings.TrimPrefix(id, p)
	}
	if digestRefRE.MatchString(id) {
		return id
	}
	return ""
}

var localIDRE = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)

// LocalID returns the image ID from a container status imageID that has no registry
// digest ("sha256:...", "docker://sha256:..." or bare hex), as "sha256:...", or "".
func LocalID(imageID string) string {
	id := strings.TrimPrefix(imageID, "docker://")
	if !localIDRE.MatchString(id) {
		return ""
	}
	if !strings.HasPrefix(id, "sha256:") {
		id = "sha256:" + id
	}
	return id
}

// Digest returns the sha256 digest in a reference, or "".
func Digest(ref string) string {
	if i := strings.LastIndex(ref, "@"); i >= 0 && strings.HasPrefix(ref[i+1:], "sha256:") {
		return ref[i+1:]
	}
	return ""
}

// Repository strips the tag and digest from an image reference: "php:8.4@sha256:..."
// and "localhost:5000/app:1" become "php" and "localhost:5000/app".
func Repository(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		ref = ref[:i]
	}
	return ref
}

// Tagged reports whether a spec image is a tag (explicit or the implicit "latest")
// rather than a digest pin, so the tag can have moved since the pod pulled it.
func Tagged(ref string) bool { return Digest(ref) == "" }

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
