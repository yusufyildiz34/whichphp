package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yusufyildiz34/whichphp/internal/verdict"
)

const (
	digestOld = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestNew = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

var testPods = `{"items":[
 {"metadata":{"namespace":"shop","name":"web-1","labels":{"pod-template-hash":"abc"},
   "ownerReferences":[{"kind":"ReplicaSet","name":"web-abc","controller":true}]},
  "spec":{"nodeName":"n1","containers":[{"name":"php","image":"php:8.4-apache","imagePullPolicy":"Always"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"php","imageID":"docker.io/library/php@` + digestOld + `"}]}},
 {"metadata":{"namespace":"kube-system","name":"coredns-1"},
  "spec":{"nodeName":"n1","containers":[{"name":"c","image":"coredns:1"}]},
  "status":{"phase":"Running"}}]}`

const testNodes = `{"items":[{"metadata":{"name":"n1"},"status":{"nodeInfo":{"architecture":"arm64","operatingSystem":"linux"}}}]}`

// fakeCluster replaces kubectl, the scanner and the resolver for one test.
func fakeCluster(t *testing.T, nodesErr error) *[][]string {
	t.Helper()
	var calls [][]string
	oldK, oldT, oldS, oldR, oldC := kubectl, clusterTools, clusterScan, clusterResolve, clusterContext
	t.Cleanup(func() {
		kubectl, clusterTools, clusterScan, clusterResolve, clusterContext = oldK, oldT, oldS, oldR, oldC
	})
	clusterTools = func() error { return nil }
	t.Setenv("KUBECONFIG", "")
	kubectl = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		for i, a := range args {
			if a == "get" && i+1 < len(args) {
				switch args[i+1] {
				case "pods":
					return []byte(testPods), nil
				case "nodes":
					if nodesErr != nil {
						return nil, nodesErr
					}
					return []byte(testNodes), nil
				}
			}
		}
		return nil, errors.New("unexpected kubectl call")
	}
	clusterScan = func(_ context.Context, f *imageFlags, input, platform string, _ io.Writer, _ feedCache) (verdict.Report, error) {
		if !f.quiet {
			t.Error("cluster scans must be quiet")
		}
		v := verdict.Vulnerable
		action := verdict.ActionNeeded
		if strings.HasSuffix(input, digestNew) {
			v, action = verdict.Fixed, verdict.ActionOK
		}
		return verdict.Report{Action: action, PHP: []verdict.PHP{{Name: "php-cli", Version: "8.4.26"}},
			Verdicts: map[string]verdict.Verdict{"CVE-2026-109618": v}}, nil
	}
	clusterResolve = func(_ context.Context, ref string) (string, error) {
		if ref != "php:8.4-apache" {
			return "", errors.New("unexpected ref " + ref)
		}
		return digestNew, nil
	}
	return &calls
}

func TestClusterArguments(t *testing.T) {
	fakeCluster(t, nil)
	for _, args := range [][]string{
		{},
		{"--context", ""},
		{"--context", "-x"},
		{"--context", "lab", "-n", "--all"},
		{"--context", "lab", "-o", "sarif"},
		{"--context", "lab", "extra"},
	} {
		var stderr bytes.Buffer
		if code := run(append([]string{"cluster"}, args...), io.Discard, &stderr); code != 3 {
			t.Errorf("cluster %q: exit %d, want 3 (%s)", args, code, stderr.String())
		}
	}
}

func TestClusterRun(t *testing.T) {
	calls := fakeCluster(t, nil)
	dir := t.TempDir()
	jsonFile := filepath.Join(dir, "cluster.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"cluster", "--context", "kind-lab", "--kubeconfig", "/tmp/kc", "-o", "table", "-o", "json=" + jsonFile}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1 (action needed)\n%s\n%s", code, stdout.String(), stderr.String())
	}
	pods := strings.Join((*calls)[0], " ")
	if pods != "--context kind-lab --kubeconfig /tmp/kc --request-timeout=60s get pods -o json --all-namespaces" {
		t.Errorf("pods call: %s", pods)
	}
	if nodes := strings.Join((*calls)[1], " "); !strings.HasSuffix(nodes, "get nodes -o json") || !strings.HasPrefix(nodes, "--context kind-lab") {
		t.Errorf("nodes call: %s", nodes)
	}
	for _, c := range *calls {
		for _, a := range c {
			if a == "delete" || a == "apply" || a == "exec" || a == "rollout" {
				t.Fatalf("kubectl call isn't read-only: %v", c)
			}
		}
	}
	out := stdout.String()
	for _, want := range []string{"Context: kind-lab", "ACTION NEEDED  shop/Deployment/web", "on linux/arm64", "Redeploy: kubectl --context kind-lab --kubeconfig /tmp/kc -n shop rollout restart deployment/web", "Skipped 1 pod in system namespaces."} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	b, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Context   string
		Action    string
		Version   string
		Workloads []struct{ Redeploy bool }
	}
	if err := json.Unmarshal(b, &res); err != nil || res.Context != "kind-lab" || res.Action != "ACTION_NEEDED" || res.Version != version || len(res.Workloads) != 1 || !res.Workloads[0].Redeploy {
		t.Errorf("json: %+v %v\n%s", res, err, b)
	}
}

func TestClusterNamespaceAndSelector(t *testing.T) {
	calls := fakeCluster(t, nil)
	var stdout bytes.Buffer
	run([]string{"cluster", "--context", "lab", "-n", "kube-system", "-l", "app=x", "-o", "json"}, &stdout, io.Discard)
	if pods := strings.Join((*calls)[0], " "); !strings.HasSuffix(pods, "get pods -o json -n kube-system -l app=x") {
		t.Errorf("pods call: %s", pods)
	}
	// Naming a namespace checks it, even a system one.
	if !strings.Contains(stdout.String(), `"namespace": "kube-system"`) {
		t.Errorf("kube-system skipped although asked for:\n%s", stdout.String())
	}
}

func TestClusterWithoutNodeAccess(t *testing.T) {
	fakeCluster(t, errors.New("kubectl --kubeconfig /home/me/kc get nodes:\nError from server (Forbidden): nodes is forbidden ::warning::x ##[group]y"))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab"}, &stdout, &stderr); code != 1 {
		t.Errorf("exit %d", code)
	}
	if out := stdout.String(); strings.Count(out, "Couldn't list nodes") != 1 || strings.Contains(out, "/home/me") {
		t.Errorf("want one note about nodes, without local paths:\n%s", out)
	}
	if !strings.Contains(stderr.String(), "couldn't list nodes: Error from server (Forbidden): nodes is forbidden") || strings.Contains(stderr.String(), "##[") {
		t.Errorf("stderr lacks the reason, or isn't cleaned:\n%s", stderr.String())
	}
}

// Checking nothing must not pass a CI gate.
func TestClusterNothingToCheck(t *testing.T) {
	fakeCluster(t, nil)
	kubectl = func(context.Context, ...string) ([]byte, error) { return []byte(`{"items":[]}`), nil }
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab", "-n", "typo"}, io.Discard, &stderr); code != 3 || !strings.Contains(stderr.String(), "no running pods") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestClusterMissingTools(t *testing.T) {
	calls := fakeCluster(t, nil)
	clusterTools = func() error { return errors.New("syft not found on PATH") }
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab"}, io.Discard, &stderr); code != 3 || !strings.Contains(stderr.String(), "syft not found") || len(*calls) != 0 {
		t.Errorf("exit %d, %d kubectl calls, stderr %q", code, len(*calls), stderr.String())
	}
}

func TestClusterScanError(t *testing.T) {
	fakeCluster(t, nil)
	clusterScan = func(context.Context, *imageFlags, string, string, io.Writer, feedCache) (verdict.Report, error) {
		return verdict.Report{}, errors.New("manifest unknown")
	}
	var stdout bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab"}, &stdout, io.Discard); code != 2 || !strings.Contains(stdout.String(), "NOT CHECKED") {
		t.Errorf("exit %d:\n%s", code, stdout.String())
	}
}

// The restart command names the kubeconfig by absolute path, and -o can't overwrite it.
func TestClusterKubeconfig(t *testing.T) {
	fakeCluster(t, nil)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("kc", []byte("apiVersion: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	run([]string{"cluster", "--context", "lab", "--kubeconfig", "kc"}, &stdout, io.Discard)
	abs, _ := filepath.Abs("kc")
	if want := "Redeploy: kubectl --context lab --kubeconfig " + abs + " -n shop rollout restart deployment/web"; !strings.Contains(stdout.String(), want) {
		t.Errorf("table lacks %q:\n%s", want, stdout.String())
	}
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab", "--kubeconfig", "kc", "-o", "json=" + abs}, io.Discard, &stderr); code != 3 {
		t.Errorf("-o onto the kubeconfig: exit %d (%s)", code, stderr.String())
	}
	if b, _ := os.ReadFile("kc"); string(b) != "apiVersion: v1\n" {
		t.Errorf("kubeconfig overwritten: %q", b)
	}
}

func TestClusterKubectlFailure(t *testing.T) {
	fakeCluster(t, nil)
	kubectl = func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("context \"lab\" not found")
	}
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab"}, io.Discard, &stderr); code != 3 || !strings.Contains(stderr.String(), "not found") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

// The real kubectl runner: arguments go through unchanged and without a shell, and a
// failure reports kubectl's own error message.
func TestKubectlRunner(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := filepath.Join(dir, "kubectl")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + log + "\nif [ \"$3\" = fail ]; then echo 'error: context \"fail\" not found' >&2; exit 1; fi\necho '{\"items\":[]}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHICHPHP_KUBECTL", script)
	out, err := kubectl(context.Background(), "--context", "a b;$(id)", "get", "pods")
	if err != nil || strings.TrimSpace(string(out)) != `{"items":[]}` {
		t.Fatalf("got %q, %v", out, err)
	}
	if b, _ := os.ReadFile(log); string(b) != "--context\na b;$(id)\nget\npods\n" {
		t.Errorf("arguments: %q", b)
	}
	if _, err := kubectl(context.Background(), "--context", "x", "fail"); err == nil || !strings.Contains(err.Error(), `context "fail" not found`) {
		t.Errorf("error: %v", err)
	}
	t.Setenv("WHICHPHP_KUBECTL", filepath.Join(dir, "missing"))
	if _, err := kubectl(context.Background(), "version"); err == nil || !strings.Contains(err.Error(), "kubectl not found") {
		t.Errorf("missing kubectl: %v", err)
	}
}

// Without --kubeconfig, the restart command carries the KUBECONFIG kubectl read.
func TestClusterKubeconfigEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("several KUBECONFIG files get no restart command on Windows")
	}
	fakeCluster(t, nil)
	t.Chdir(t.TempDir())
	t.Setenv("KUBECONFIG", "prod.yaml"+string(filepath.ListSeparator)+"/etc/kube/extra.yaml")
	var stdout bytes.Buffer
	run([]string{"cluster", "--context", "kubernetes-admin@kubernetes"}, &stdout, io.Discard)
	abs, _ := filepath.Abs("prod.yaml")
	want := "Redeploy: KUBECONFIG=" + abs + string(filepath.ListSeparator) + "/etc/kube/extra.yaml kubectl --context kubernetes-admin@kubernetes -n shop rollout restart deployment/web"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("table lacks %q:\n%s", want, stdout.String())
	}
}

// Ctrl-C during the scans stops the run with exit 3 and writes no report.
func TestClusterInterrupted(t *testing.T) {
	fakeCluster(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	clusterContext = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	scan := clusterScan
	clusterScan = func(c context.Context, f *imageFlags, input, platform string, w io.Writer, fc feedCache) (verdict.Report, error) {
		cancel()
		return scan(c, f, input, platform, w, fc)
	}
	out := filepath.Join(t.TempDir(), "cluster.json")
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab", "-o", "json=" + out}, io.Discard, &stderr); code != 3 || !strings.Contains(stderr.String(), "interrupted") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a report was written for an interrupted run")
	}
}

// One KUBECONFIG file becomes --kubeconfig, which works in any shell; -o can't
// overwrite a kubeconfig named there either.
func TestClusterSingleKubeconfigEnv(t *testing.T) {
	fakeCluster(t, nil)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("prod.yaml", []byte("apiVersion: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", "prod.yaml")
	abs, _ := filepath.Abs("prod.yaml")
	var stdout bytes.Buffer
	run([]string{"cluster", "--context", "lab"}, &stdout, io.Discard)
	if want := "Redeploy: kubectl --context lab --kubeconfig " + abs + " -n shop"; !strings.Contains(stdout.String(), want) {
		t.Errorf("table lacks %q:\n%s", want, stdout.String())
	}
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab", "-o", "json=prod.yaml"}, io.Discard, &stderr); code != 3 {
		t.Errorf("-o onto the KUBECONFIG file: exit %d (%s)", code, stderr.String())
	}
	if b, _ := os.ReadFile("prod.yaml"); string(b) != "apiVersion: v1\n" {
		t.Errorf("kubeconfig overwritten: %q", b)
	}
}

// The default kubeconfig is protected from -o even when --kubeconfig names another.
func TestClusterProtectsHomeKubeconfig(t *testing.T) {
	fakeCluster(t, nil)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := filepath.Join(home, ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("apiVersion: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"cluster", "--context", "lab", "--kubeconfig", filepath.Join(t.TempDir(), "other.yaml"), "-o", "json=" + cfg}, io.Discard, &stderr); code != 3 {
		t.Errorf("-o onto ~/.kube/config: exit %d (%s)", code, stderr.String())
	}
	if b, _ := os.ReadFile(cfg); string(b) != "apiVersion: v1\n" {
		t.Errorf("default kubeconfig overwritten: %q", b)
	}
}
