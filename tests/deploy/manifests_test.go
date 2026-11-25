// Package deploy checks deploy/kubernetes for internal consistency and against the code, with no cluster involved: every
// object is named and namespaced, both pods are hardened, the mounts, ports and settings agree with each other and with
// what the binaries read, nothing test-only is shipped, the renderer may reach only the proxy, and the proxy's egress policy
// excludes exactly the IPv4 addresses internal/addr refuses. It cannot show that a CNI enforces the policies: that is the
// platform's kind run (L1-4).
package deploy

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"idp-browser/internal/addr"
)

const (
	dir = "../../deploy/kubernetes"
	ns  = "idp-browser"
)

type doc = map[string]any

func load(t *testing.T, name string) []doc {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	var out []doc
	for {
		var d doc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

func get(d any, path ...string) any {
	for _, p := range path {
		m, ok := d.(doc)
		if !ok {
			return nil
		}
		d = m[p]
	}
	return d
}

func str(d any, path ...string) string { s, _ := get(d, path...).(string); return s }
func list(d any, path ...string) []any { l, _ := get(d, path...).([]any); return l }
func name(d doc) string                { return str(d, "kind") + "/" + str(d, "metadata", "name") }

func strs(l []any) []string {
	var out []string
	for _, v := range l {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

type manifests struct {
	kust   doc
	docs   []doc
	byKind map[string][]doc
}

func loadAll(t *testing.T) *manifests {
	t.Helper()
	m := &manifests{kust: load(t, "kustomization.yaml")[0], byKind: map[string][]doc{}}
	for _, r := range list(m.kust, "resources") {
		for _, d := range load(t, r.(string)) {
			m.docs = append(m.docs, d)
			m.byKind[str(d, "kind")] = append(m.byKind[str(d, "kind")], d)
		}
	}
	return m
}

func (m *manifests) deployment(t *testing.T, component string) doc {
	t.Helper()
	for _, d := range m.byKind["Deployment"] {
		if str(d, "metadata", "labels", "app.kubernetes.io/component") == component {
			return d
		}
	}
	t.Fatalf("no %s deployment", component)
	return nil
}

func envOf(container any) map[string]string {
	out := map[string]string{}
	for _, e := range list(container, "env") {
		out[str(e, "name")] = str(e, "value")
	}
	return out
}

func TestKustomizationListsEveryFileAndUsesLabelsNotCommonLabels(t *testing.T) {
	m := loadAll(t)
	if m.kust["commonLabels"] != nil || m.kust["namespace"] != nil {
		t.Error("commonLabels rewrites NetworkPolicy peer selectors (idp-web, kube-dns), which then match nothing")
	}
	listed := map[string]bool{"kustomization.yaml": true}
	for _, r := range list(m.kust, "resources") {
		listed[r.(string)] = true
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !listed[e.Name()] {
			t.Errorf("%s is not used by the kustomization", e.Name())
		}
		if n := strings.ToLower(e.Name()); strings.Contains(n, "key") || strings.Contains(n, "secret") {
			t.Errorf("%s: a key or secret does not belong in the repository", e.Name())
		}
	}
	imgs := map[string]doc{}
	for _, i := range list(m.kust, "images") {
		imgs[str(i, "name")] = i.(doc)
	}
	for _, n := range []string{"idp-browser", "idp-browser-proxy"} {
		i := imgs[n]
		if i == nil || !strings.HasPrefix(str(i, "digest"), "sha256:") || !strings.HasPrefix(str(i, "newName"), "registry.example.com/idp/") {
			t.Errorf("the image %s is not a placeholder pinned by digest: %v", n, i)
		}
	}
	if len(imgs) != 2 {
		t.Errorf("images: %v", imgs)
	}
}

func TestEveryManifestIsNamedAndInTheNamespace(t *testing.T) {
	for _, d := range loadAll(t).docs {
		if str(d, "apiVersion") == "" || str(d, "kind") == "" || str(d, "metadata", "name") == "" {
			t.Errorf("incomplete object: %v", d)
		}
		switch k := str(d, "kind"); k {
		case "Namespace":
			if str(d, "metadata", "name") != ns {
				t.Errorf("namespace %s", name(d))
			}
		case "Secret", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "ServiceAccount":
			t.Errorf("%s does not belong here: the operator creates the secrets, and no pod has a credential for the API", name(d))
		default:
			if got := str(d, "metadata", "namespace"); got != ns {
				t.Errorf("%s: namespace %q", name(d), got)
			}
		}
	}
}

func TestNamespaceIsRestrictedAndBounded(t *testing.T) {
	m := loadAll(t)
	l, _ := get(m.byKind["Namespace"][0], "metadata", "labels").(doc)
	if l["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Errorf("labels %v", l)
	}
	if len(m.byKind["ResourceQuota"]) != 1 || get(m.byKind["ResourceQuota"][0], "spec", "hard", "limits.memory") == nil {
		t.Error("no quota on memory: Chromium is the platform's biggest memory user")
	}
}

func TestBothPodsAreHardened(t *testing.T) {
	m := loadAll(t)
	for comp, user := range map[string]int{"renderer": 10600, "proxy": 10601} {
		dep := m.deployment(t, comp)
		pod := get(dep, "spec", "template", "spec")
		if get(pod, "automountServiceAccountToken") != false || get(pod, "enableServiceLinks") != false || get(pod, "hostNetwork") != nil ||
			get(pod, "hostPID") != nil || get(pod, "shareProcessNamespace") != nil {
			t.Errorf("%s: service account token, service links or host namespaces", comp)
		}
		if get(pod, "securityContext", "runAsNonRoot") != true || get(pod, "securityContext", "runAsUser") != user || str(pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
			t.Errorf("%s: pod security context %v", comp, get(pod, "securityContext"))
		}
		cs := list(pod, "containers")
		if len(cs) != 1 {
			t.Fatalf("%s: %d containers", comp, len(cs))
		}
		c := cs[0]
		sc := get(c, "securityContext")
		if get(sc, "allowPrivilegeEscalation") != false || get(sc, "readOnlyRootFilesystem") != true || get(sc, "privileged") != nil ||
			strings.Join(strs(list(sc, "capabilities", "drop")), ",") != "ALL" || list(sc, "capabilities", "add") != nil ||
			get(c, "resources", "limits", "memory") == nil || get(c, "resources", "limits", "cpu") == nil ||
			get(c, "resources", "requests", "memory") == nil || get(c, "resources", "requests", "cpu") == nil {
			t.Errorf("%s: container %v", comp, c)
		}
	}
	if str(m.deployment(t, "proxy"), "spec", "strategy", "type") != "Recreate" {
		t.Error("the proxy keeps its renders in memory: two pods at once would split a render's registration and its requests")
	}
}

// ADR-0001 D9: Chromium's sandbox is off only under gVisor or Kata, and the pod says which, in the object and in the setting.
func TestTheRendererRunsUnderARuntimeClassThatIsTheSandboxAndSaysSo(t *testing.T) {
	m := loadAll(t)
	dep := m.deployment(t, "renderer")
	pod := get(dep, "spec", "template", "spec")
	rc := str(pod, "runtimeClassName")
	if rc == "" {
		t.Fatal("no runtimeClassName: with --no-sandbox the RuntimeClass is the only sandbox")
	}
	env := envOf(list(pod, "containers")[0])
	if env["IDP_BROWSER_NO_SANDBOX"] == "true" && env["IDP_BROWSER_ISOLATED_BY"] != "gvisor" && env["IDP_BROWSER_ISOLATED_BY"] != "kata" {
		t.Errorf("--no-sandbox without the statement: %q", env["IDP_BROWSER_ISOLATED_BY"])
	}
	// the settings file is the one place the two are chosen, and the kustomization copies both into the object
	var settings doc
	for _, d := range m.byKind["ConfigMap"] {
		if str(d, "metadata", "name") == "idp-browser-settings" {
			settings = d
		}
	}
	if settings == nil || str(settings, "data", "runtimeClass") == "" || str(settings, "data", "isolatedBy") == "" {
		t.Fatalf("settings: %v", settings)
	}
	if got := list(m.kust, "replacements"); len(got) != 2 {
		t.Errorf("replacements %v", got)
	}
	if v := str(settings, "data", "isolatedBy"); v != "gvisor" && v != "kata" {
		t.Errorf("isolatedBy %q", v)
	}
	if rc != str(settings, "data", "runtimeClass") || env["IDP_BROWSER_ISOLATED_BY"] != str(settings, "data", "isolatedBy") {
		t.Errorf("the object (%s, %s) and the settings file disagree", rc, env["IDP_BROWSER_ISOLATED_BY"])
	}
}

// What the binaries read: every setting a manifest sets is one the code knows, and the files it points to are mounted.
func TestSettingsAreKnownToTheCodeAndTheirFilesAreMounted(t *testing.T) {
	m := loadAll(t)
	known := map[string]bool{}
	for _, src := range []string{"../../cmd/idp-browser/main.go", "../../cmd/idp-browser-proxy/main.go"} {
		b, _ := os.ReadFile(src)
		for _, v := range regexp.MustCompile(`IDP_BROWSER_[A-Z_]+`).FindAllString(string(b), -1) {
			known[v] = true
		}
	}
	for _, comp := range []string{"renderer", "proxy"} {
		pod := get(m.deployment(t, comp), "spec", "template", "spec")
		c := list(pod, "containers")[0]
		mounts := map[string]string{}
		for _, v := range list(c, "volumeMounts") {
			mounts[str(v, "name")] = str(v, "mountPath")
		}
		volumes := map[string]bool{}
		for _, v := range list(pod, "volumes") {
			volumes[str(v, "name")] = true
		}
		for n := range mounts {
			if !volumes[n] {
				t.Errorf("%s: mount %s has no volume", comp, n)
			}
		}
		for k, v := range envOf(c) {
			if !known[k] {
				t.Errorf("%s: %s is not a setting of the code", comp, k)
			}
			if strings.HasSuffix(k, "_FILE") {
				ok := false
				for _, p := range mounts {
					ok = ok || strings.HasPrefix(v, p+"/")
				}
				if !ok {
					t.Errorf("%s: %s=%s is not under a mount", comp, k, v)
				}
			}
		}
		// the ports the probes and the services use are declared
		declared := map[string]bool{}
		for _, p := range list(c, "ports") {
			declared[str(p, "name")] = true
		}
		for _, probe := range []string{"readinessProbe", "livenessProbe"} {
			if p := str(c, probe, "httpGet", "port"); !declared[p] {
				t.Errorf("%s: %s uses port %q", comp, probe, p)
			}
		}
	}
	r := envOf(list(get(m.deployment(t, "renderer"), "spec", "template", "spec"), "containers")[0])
	if !strings.HasPrefix(r["IDP_BROWSER_PROXY"], "idp-browser-proxy.idp-browser.svc") || !strings.HasSuffix(r["IDP_BROWSER_PROXY"], ":3128") ||
		!strings.HasSuffix(r["IDP_BROWSER_PROXY_ADMIN"], ":3129") || r["IDP_BROWSER_CALLER_AUDIENCE"] != "http://idp-browser.idp-browser.svc.cluster.local:8590/render" {
		t.Errorf("renderer settings %v", r)
	}
	// the proxy's own list of ports is the renderer's
	p := envOf(list(get(m.deployment(t, "proxy"), "spec", "template", "spec"), "containers")[0])
	if p["IDP_BROWSER_PORTS"] != "80,443" || r["IDP_BROWSER_PORTS"] != "" && r["IDP_BROWSER_PORTS"] != p["IDP_BROWSER_PORTS"] {
		t.Errorf("ports: proxy %q renderer %q", p["IDP_BROWSER_PORTS"], r["IDP_BROWSER_PORTS"])
	}
	for _, s := range m.byKind["Service"] {
		if str(s, "metadata", "name") == "idp-browser-proxy" && str(s, "spec", "sessionAffinity") != "ClientIP" {
			t.Error("the proxy Service has no ClientIP affinity: a render's registration and its requests may reach different pods")
		}
	}
}

func TestNothingTestOnlyIsShipped(t *testing.T) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "IDP_BROWSER_TEST_ORIGINS") && !(e.Name() == "renderer.yaml" && strings.Contains(line, "Never IDP_BROWSER_TEST_ORIGINS")) {
				t.Errorf("%s:%d mentions IDP_BROWSER_TEST_ORIGINS: %s", e.Name(), i+1, line)
			}
			if strings.Contains(strings.ToLower(line), "spki") || strings.Contains(line, "ignore-certificate-errors") {
				t.Errorf("%s:%d: a certificate exception: %s", e.Name(), i+1, line)
			}
		}
	}
	m := loadAll(t)
	for _, comp := range []string{"renderer", "proxy"} {
		for k := range envOf(list(get(m.deployment(t, comp), "spec", "template", "spec"), "containers")[0]) {
			if strings.Contains(k, "TEST") {
				t.Errorf("%s ships %s", comp, k)
			}
		}
	}
}

var secretish = regexp.MustCompile(`(?i)(BEGIN [A-Z ]*(PRIVATE|PUBLIC) KEY|[A-Za-z0-9+/]{40,}={0,2}$)`)

func TestNoKeyMaterialInTheFiles(t *testing.T) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for i, line := range strings.Split(string(b), "\n") {
			if secretish.MatchString(strings.TrimSpace(line)) && !strings.Contains(line, "sha256:") {
				t.Errorf("%s:%d looks like key material", e.Name(), i+1)
			}
		}
	}
}

func policy(t *testing.T, m *manifests, name string) doc {
	t.Helper()
	for _, p := range m.byKind["NetworkPolicy"] {
		if str(p, "metadata", "name") == name {
			return p
		}
	}
	t.Fatalf("no policy %s", name)
	return nil
}

func ports(rule any) []int {
	var out []int
	for _, p := range list(rule, "ports") {
		out = append(out, get(p, "port").(int))
	}
	sort.Ints(out)
	return out
}

func component(p doc) string {
	sel, _ := get(p, "spec", "podSelector", "matchLabels").(doc)
	s, _ := sel["app.kubernetes.io/component"].(string)
	return s
}

// The rule of ADR-0001 D12: the renderer reaches the proxy and nothing else (and DNS); the proxy reaches the internet and
// not the cluster; idp-web alone reaches the renderer; the renderer pods alone reach the proxy.
func TestNetworkPoliciesHoldTheFlowsOfTheADRAndNoOthers(t *testing.T) {
	m := loadAll(t)
	// default deny, both directions
	dd := policy(t, m, "default-deny")
	if len(get(dd, "spec", "podSelector").(doc)) != 0 || len(strs(list(dd, "spec", "policyTypes"))) != 2 || get(dd, "spec", "ingress") != nil || get(dd, "spec", "egress") != nil {
		t.Error("no default-deny of both directions")
	}
	// the policies that allow egress: DNS, the renderer's (the proxy), the proxy's (the internet)
	names := map[string]bool{}
	for _, p := range m.byKind["NetworkPolicy"] {
		if len(list(p, "spec", "egress")) > 0 {
			names[str(p, "metadata", "name")] = true
		}
	}
	if len(names) != 3 || !names["allow-dns"] || !names["renderer-egress"] || !names["proxy-egress"] {
		t.Errorf("policies that allow egress: %v", names)
	}
	// renderer egress: the proxy pods in this namespace, ports 3128 and 3129, nothing else
	re := policy(t, m, "renderer-egress")
	if component(re) != "renderer" {
		t.Errorf("renderer-egress selects %q", component(re))
	}
	eg := list(re, "spec", "egress")
	if len(eg) != 1 || len(list(eg[0], "to")) != 1 {
		t.Fatalf("renderer egress %v", eg)
	}
	to := list(eg[0], "to")[0]
	if get(to, "ipBlock") != nil || get(to, "namespaceSelector") != nil || str(to, "podSelector", "matchLabels", "app.kubernetes.io/component") != "proxy" {
		t.Errorf("the renderer may reach %v, not only the proxy pods of its namespace", to)
	}
	if p := ports(eg[0]); len(p) != 2 || p[0] != 3128 || p[1] != 3129 {
		t.Errorf("renderer egress ports %v", p)
	}
	// DNS: kube-dns only
	dns := list(policy(t, m, "allow-dns"), "spec", "egress")
	if len(dns) != 1 || str(list(dns[0], "to")[0], "podSelector", "matchLabels", "k8s-app") != "kube-dns" {
		t.Errorf("dns %v", dns)
	}
	// renderer ingress: idp-web's pods on the API port; ops from observability
	ri := list(policy(t, m, "renderer-ingress"), "spec", "ingress")
	if len(ri) != 2 {
		t.Fatalf("renderer ingress %v", ri)
	}
	from := list(ri[0], "from")
	if len(from) != 1 || str(from[0], "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "idp-web" ||
		str(from[0], "podSelector", "matchLabels", "app.kubernetes.io/component") != "web" || get(from[0], "ipBlock") != nil {
		t.Errorf("the API port may be reached from %v: only idp-web's pods", from)
	}
	if p := ports(ri[0]); len(p) != 1 || p[0] != 8590 {
		t.Errorf("api ports %v", p)
	}
	if p := ports(ri[1]); len(p) != 1 || p[0] != 9590 {
		t.Errorf("ops ports %v", p)
	}
	// proxy ingress: the renderer pods on 3128 and 3129
	pi := list(policy(t, m, "proxy-ingress"), "spec", "ingress")
	if len(pi) != 2 {
		t.Fatalf("proxy ingress %v", pi)
	}
	pf := list(pi[0], "from")
	if len(pf) != 1 || str(pf[0], "podSelector", "matchLabels", "app.kubernetes.io/component") != "renderer" || get(pf[0], "namespaceSelector") != nil || get(pf[0], "ipBlock") != nil {
		t.Errorf("the proxy may be reached from %v: only the renderer pods", pf)
	}
	if p := ports(pi[0]); len(p) != 2 || p[0] != 3128 || p[1] != 3129 {
		t.Errorf("proxy ingress ports %v", p)
	}
}

func TestProxyEgressIsThePublicInternetOnTheListedPortsAndIPv4Only(t *testing.T) {
	m := loadAll(t)
	pe := policy(t, m, "proxy-egress")
	if component(pe) != "proxy" {
		t.Errorf("selects %q", component(pe))
	}
	eg := list(pe, "spec", "egress")
	if len(eg) != 1 || len(list(eg[0], "to")) != 1 {
		t.Fatalf("egress %v", eg)
	}
	to := list(eg[0], "to")[0]
	if get(to, "namespaceSelector") != nil || get(to, "podSelector") != nil || str(to, "ipBlock", "cidr") != "0.0.0.0/0" {
		t.Fatalf("egress peer %v: IPv4 addresses outside the cluster only (an IPv6 rule needs its own excepts)", to)
	}
	var except []netip.Prefix
	for _, c := range list(to, "ipBlock", "except") {
		p := netip.MustParsePrefix(c.(string))
		if !p.Addr().Is4() {
			t.Errorf("except %s is not IPv4", p)
		}
		except = append(except, p)
	}
	excluded := func(a netip.Addr) bool {
		for _, e := range except {
			if e.Contains(a) {
				return true
			}
		}
		return false
	}
	// What the proxy refuses to connect to, the cluster refuses too, and nothing else: every /24 of the IPv4 space is compared
	// (the smallest block of the table is a /24, and 192.0.0.0/24 is refused whole), so a block added to the code's table and
	// not here is found, and so is an except that cuts off public addresses.
	for n := uint64(0); n < 1<<32; n += 256 {
		a := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), 0})
		if refused := !addr.Public(a); refused != excluded(a) {
			t.Fatalf("%s: the proxy refuses it: %v; the policy excludes it: %v", a, refused, excluded(a))
		}
	}
	for _, a := range []string{"0.0.0.0", "10.255.255.254", "100.127.255.254", "127.0.0.1", "169.254.169.254", "172.31.255.254", "192.0.0.9", "192.168.255.254", "239.255.255.250", "255.255.255.255"} {
		if a := netip.MustParseAddr(a); !excluded(a) || addr.Public(a) {
			t.Errorf("%s: excluded %v, public per the code %v", a, excluded(a), addr.Public(a))
		}
	}
	for _, a := range []string{"1.1.1.1", "93.184.216.34", "151.101.0.223", "192.31.196.1"} {
		if excluded(netip.MustParseAddr(a)) {
			t.Errorf("the public address %s is excluded", a)
		}
	}
	if p := ports(eg[0]); len(p) != 2 || p[0] != 80 || p[1] != 443 {
		t.Errorf("egress ports %v", p)
	}
}
