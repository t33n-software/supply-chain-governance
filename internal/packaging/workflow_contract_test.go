package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// bindingManifest mirrors the tenant binding manifest (repo-bindings/v1) for
// the self-consistency proofs of the canonical adoption. The home-side proof
// against the canonical masters is owned by the verify-canonical tool; these
// tests bind the tenant files to the manifest.
type bindingManifest struct {
	Home struct {
		Repository string `json:"repository"`
		SHA        string `json:"sha"`
	} `json:"home"`
	Callers []struct {
		File   string `json:"file"`
		Master string `json:"master"`
		SHA256 string `json:"sha256"`
	} `json:"callers"`
	Files struct {
		Lefthook      fileBinding      `json:"lefthook"`
		Gitattributes fileBinding      `json:"gitattributes"`
		Gitignore     gitignoreBinding `json:"gitignore"`
		Dependabot    fileBinding      `json:"dependabot"`
	} `json:"files"`
	Codeowners struct {
		Path         string `json:"path"`
		DefaultOwner string `json:"defaultOwner"`
	} `json:"codeowners"`
}

type fileBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// gitignoreBinding mirrors the fragment-composition binding of the gitignore
// topic (repo-bindings/v2): the ordered fragment list renders the governed
// region whose hash the manifest binds.
type gitignoreBinding struct {
	Path      string   `json:"path"`
	Fragments []string `json:"fragments"`
	SHA256    string   `json:"sha256"`
}

func readBindingManifest(t *testing.T) bindingManifest {
	t.Helper()
	var manifest bindingManifest
	if err := json.Unmarshal([]byte(readRepositoryFile(t, "repo-bindings.json")), &manifest); err != nil {
		t.Fatalf("repo-bindings.json is not valid JSON: %v", err)
	}
	if manifest.Home.Repository != "t33n-software/repository-governance" {
		t.Fatalf("the manifest binds home %q", manifest.Home.Repository)
	}
	return manifest
}

// hashRepositoryFile hashes the LF-normalized repository file; the canonical
// .gitattributes makes the checkout LF, and the normalization keeps the
// derivation tolerant as the second line of defense.
func hashRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	normalized := strings.ReplaceAll(readRepositoryFile(t, path), "\r\n", "\n")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func TestCanonicalCallersMatchTheBindingManifest(t *testing.T) {
	manifest := readBindingManifest(t)
	want := map[string]string{
		".github/workflows/ci.yml":                    "hosting-platforms/github/workflows/callers/go/ci.yml",
		".github/workflows/codeql.yml":                "hosting-platforms/github/workflows/callers/go/codeql.yml",
		".github/workflows/dependency-review.yml":     "hosting-platforms/github/workflows/callers/go/dependency-review.yml",
		".github/workflows/canonical-conformance.yml": "hosting-platforms/github/workflows/callers/go/canonical-conformance.yml",
	}
	if len(manifest.Callers) != len(want) {
		t.Fatalf("the manifest carries %d callers, want %d", len(manifest.Callers), len(want))
	}
	for _, caller := range manifest.Callers {
		master, found := want[caller.File]
		if !found {
			t.Fatalf("the manifest carries an unexpected caller %q", caller.File)
		}
		if caller.Master != master {
			t.Fatalf("caller %q binds master %q, want %q", caller.File, caller.Master, master)
		}
		if hash := hashRepositoryFile(t, caller.File); hash != caller.SHA256 {
			t.Fatalf("the tenant caller %s hashes to %s, want the bound %s", caller.File, hash, caller.SHA256)
		}
		content := readRepositoryFile(t, caller.File)
		if !strings.Contains(content, "uses: "+manifest.Home.Repository+"/.github/workflows/reusable-") {
			t.Fatalf("the tenant caller %s does not reference a home payload", caller.File)
		}
		if !strings.Contains(content, "@"+manifest.Home.SHA) {
			t.Fatalf("the tenant caller %s does not pin the bound home SHA", caller.File)
		}
		if !strings.Contains(content, `branches: [main, develop, "release/**", "support/**"]`) {
			t.Fatalf("the tenant caller %s does not cover every shared line", caller.File)
		}
	}
}

func TestCanonicalFileFamilyMatchesTheBindingManifest(t *testing.T) {
	manifest := readBindingManifest(t)
	for _, topic := range []fileBinding{
		manifest.Files.Lefthook,
		manifest.Files.Gitattributes,
		manifest.Files.Dependabot,
	} {
		if hash := hashRepositoryFile(t, topic.Path); hash != topic.SHA256 {
			t.Fatalf("the canonical file %s hashes to %s, want the bound %s", topic.Path, hash, topic.SHA256)
		}
	}
	// The gitignore topic is the fragment-composition form in the home
	// verifier: the bound fragment list renders the governed region at the
	// bound home pin, and the tenant file carries that region as a verbatim
	// prefix with the free project block below exactly one mark. The
	// home-side re-render proof against the pinned tree is owned by the
	// verify-canonical tool; this test binds the tenant file to the
	// manifest.
	gitignore := strings.ReplaceAll(readRepositoryFile(t, manifest.Files.Gitignore.Path), "\r\n", "\n")
	stamp := "# canonical: gitignore " + strings.Join(manifest.Files.Gitignore.Fragments, " + ") + " @ " + manifest.Home.SHA + " — governed region, do not edit\n"
	if !strings.HasPrefix(gitignore, stamp) {
		t.Fatal("the gitignore does not carry the canonical stamp of the bound fragments at the bound home pin")
	}
	const projectBlockMark = "# -- project additions below this line --"
	if strings.Count(gitignore, projectBlockMark) != 1 {
		t.Fatal("the gitignore does not carry exactly one project-block mark")
	}
	region, _, _ := strings.Cut(gitignore, projectBlockMark+"\n")
	region += projectBlockMark + "\n"
	if sum := sha256.Sum256([]byte(region)); hex.EncodeToString(sum[:]) != manifest.Files.Gitignore.SHA256 {
		t.Fatalf("the gitignore governed region hashes to %s, want the bound %s", hex.EncodeToString(sum[:]), manifest.Files.Gitignore.SHA256)
	}

	codeowners := readRepositoryFile(t, manifest.Codeowners.Path)
	if !strings.Contains(codeowners, "* "+manifest.Codeowners.DefaultOwner) {
		t.Fatalf("the ownership file does not bind the default owner %q", manifest.Codeowners.DefaultOwner)
	}
}

func TestConformanceWorkflowBindsTheVerifier(t *testing.T) {
	manifest := readBindingManifest(t)
	content := readRepositoryFile(t, ".github/workflows/canonical-conformance.yml")
	for _, required := range []string{
		"permissions: {}",
		"name: Canonical conformance",
		"uses: " + manifest.Home.Repository + "/.github/workflows/reusable-canonical-conformance.yml@" + manifest.Home.SHA,
		`branches: [main, develop, "release/**", "support/**"]`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("the canonical conformance workflow does not contain %q", required)
		}
	}
}

func TestOrganizationRulesetAdoptionHasNoLocalLegacyDefinitions(t *testing.T) {
	if _, err := os.Stat(repositoryPath("docs", "hosting-platforms")); !os.IsNotExist(err) {
		t.Fatalf("legacy ruleset location must not exist")
	}

	conventions := readRepositoryFile(t, filepath.Join("docs", "conventions", "hosting-plattform", "github", "rule-sets", "README.md"))
	for _, required := range []string{
		"git-governance",
		"quality-gates=linux-only",
		"~ALL",
	} {
		if !strings.Contains(conventions, required) {
			t.Fatalf("rule-set conventions README does not contain %q", required)
		}
	}
}

func TestModuleIdentityAndQualityContract(t *testing.T) {
	goMod := readRepositoryFile(t, "go.mod")
	for _, required := range []string{
		"module github.com/t33n-software/supply-chain-governance",
		"go 1.26",
		"toolchain go1.26.6",
	} {
		if !strings.Contains(goMod, required) {
			t.Fatalf("go.mod does not contain %q", required)
		}
	}

	quality := readRepositoryFile(t, "git-governance.quality.json")
	var qualityConfig struct {
		SchemaVersion int `json:"schemaVersion"`
		Gates         []struct {
			Name    string   `json:"name"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"gates"`
		Project struct {
			Binaries []struct {
				Package string `json:"package"`
			} `json:"binaries"`
		} `json:"project"`
	}
	if err := json.Unmarshal([]byte(quality), &qualityConfig); err != nil {
		t.Fatalf("git-governance.quality.json is not valid JSON: %v", err)
	}
	if qualityConfig.SchemaVersion != 4 {
		t.Fatalf("git-governance.quality.json carries schemaVersion %d, want 4", qualityConfig.SchemaVersion)
	}
	if len(qualityConfig.Gates) != 2 {
		t.Fatalf("git-governance.quality.json carries %d gates, want the canonical gate chain plus the conformance project gate", len(qualityConfig.Gates))
	}
	if qualityConfig.Gates[0].Name != "supply-chain-governance-source-quality" ||
		qualityConfig.Gates[0].Command != "go" ||
		!slices.Equal(qualityConfig.Gates[0].Args, []string{"tool", "-modfile", "tools/go.mod", "quality-gate"}) {
		t.Fatal("the first gate does not invoke the canonical gate chain through the tooling module pin")
	}
	if qualityConfig.Gates[1].Name != "conformance-vectors" ||
		qualityConfig.Gates[1].Command != "go" ||
		!slices.Equal(qualityConfig.Gates[1].Args, []string{"run", "-mod=readonly", "./cmd/check-conformance"}) {
		t.Fatal("the second gate does not run the repository conformance harness")
	}
	if len(qualityConfig.Project.Binaries) != 1 || qualityConfig.Project.Binaries[0].Package != "./cmd/check-conformance" {
		t.Fatal("the project binaries must carry only the conformance harness")
	}
	for _, forbidden := range []string{`"./cmd/build"`, `"./cmd/check-coverage"`, `"defaults"`} {
		if strings.Contains(quality, forbidden) {
			t.Fatalf("git-governance.quality.json still contains %s", forbidden)
		}
	}
	for _, chainCopy := range []string{"cmd/build", "cmd/check-coverage"} {
		if _, err := os.Stat(repositoryPath(filepath.FromSlash(chainCopy))); !os.IsNotExist(err) {
			t.Fatalf("the repo-local gate chain copy %s must not exist", chainCopy)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	if !strings.Contains(lefthook, "git-governance --interactive never validate pre-push --remote") {
		t.Fatal("lefthook.yml does not bind the canonical pre-push validation")
	}
}

func TestGoToolchainAndBuildToolingContract(t *testing.T) {
	toolsMod := readRepositoryFile(t, filepath.Join("tools", "go.mod"))
	for _, required := range []string{
		"module github.com/t33n-software/supply-chain-governance/tools",
		"toolchain go1.26.6",
		"github.com/evilmartians/lefthook/v2",
		"golang.org/x/vuln/cmd/govulncheck",
		"honnef.co/go/tools/cmd/staticcheck",
		"github.com/t33n-software/go-quality-authority/cmd/quality-gate",
		"github.com/t33n-software/go-quality-authority/cmd/check-coverage",
		"github.com/t33n-software/repository-governance/cmd/verify-canonical",
	} {
		if !strings.Contains(toolsMod, required) {
			t.Fatalf("tools/go.mod does not contain %q", required)
		}
	}
	if _, err := os.Stat(repositoryPath("tools", "go.sum")); err != nil {
		t.Fatalf("tools/go.sum is missing: %v", err)
	}

	manifest := readBindingManifest(t)
	for _, caller := range []string{"ci.yml", "codeql.yml"} {
		content := readRepositoryFile(t, ".github/workflows/"+caller)
		if !strings.Contains(content, "uses: "+manifest.Home.Repository+"/.github/workflows/reusable-") {
			t.Fatalf("the caller %s does not reference a home payload", caller)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	for _, required := range []string{
		"commit-msg:",
		`git-governance --interactive never commit validate --message-file "{1}"`,
		"pre-push:",
		`git-governance --interactive never validate pre-push --remote "{1}"`,
	} {
		if !strings.Contains(lefthook, required) {
			t.Fatalf("lefthook.yml does not contain %q", required)
		}
	}

	traceability := readRepositoryFile(t, filepath.Join("docs", "TRACEABILITY.md"))
	if !strings.Contains(traceability, "SCG-3") {
		t.Fatal("TRACEABILITY.md does not contain SCG-3")
	}
}

func TestGovernanceDocumentationPreservesCoreInstanceAndTenantBoundaries(t *testing.T) {
	for _, path := range []string{
		"README.md",
		"docs/architecture/ADR-0001-SUPPLY-CHAIN-GOVERNANCE.md",
		"docs/development/VERIFICATION.md",
	} {
		content := strings.ToLower(readRepositoryFile(t, path))
		for _, required := range []string{"core", "instance", "tenant"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s does not document %q boundary", path, required)
			}
		}
	}

	adr := readRepositoryFile(t, "docs/architecture/ADR-0001-SUPPLY-CHAIN-GOVERNANCE.md")
	for _, required := range []string{
		"never contains concrete organization",
		"never contains tenant",
		"evidence-graph/v1",
	} {
		if !strings.Contains(adr, required) {
			t.Fatalf("ADR does not contain %q", required)
		}
	}
}

func TestConformanceVectorsAndShippedPoliciesArePresent(t *testing.T) {
	positiveDirectory := repositoryPath("schemas", "evidence-graph", "conformance", "positive")
	for _, name := range []string{
		"source.subject.json",
		"dependency-resolution.subject.json",
		"build.subject.json",
		"artifact.subject.json",
		"promotion.subject.json",
		"deployment.subject.json",
		"operation.subject.json",
	} {
		if _, err := os.Stat(filepath.Join(positiveDirectory, name)); err != nil {
			t.Fatalf("missing positive vector %q: %v", name, err)
		}
	}

	for _, directory := range []string{
		repositoryPath("schemas", "evidence-graph", "conformance", "negative"),
		repositoryPath("conformance", "positive"),
		repositoryPath("conformance", "negative"),
		repositoryPath("capabilities", "infrastructure", "opentofu", "conformance", "positive"),
		repositoryPath("capabilities", "infrastructure", "opentofu", "conformance", "negative"),
		repositoryPath("capabilities", "security", "cosign", "conformance", "positive"),
		repositoryPath("capabilities", "security", "cosign", "conformance", "negative"),
		repositoryPath("schemas", "quality-gate-config", "conformance", "positive"),
		repositoryPath("schemas", "quality-gate-config", "conformance", "negative"),
	} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("ReadDir(%q) error = %v", directory, err)
		}
		if len(entries) == 0 {
			t.Fatalf("vector directory %q is empty", directory)
		}
	}

	for _, ecosystem := range []string{"go", "npm", "python"} {
		policyPath := repositoryPath("policies", "dependency", ecosystem, "policy.json")
		if _, err := os.Stat(policyPath); err != nil {
			t.Fatalf("missing shipped policy %q: %v", policyPath, err)
		}
	}

	for _, descriptor := range []string{
		repositoryPath("capabilities", "infrastructure", "opentofu", "v1", "pack.json"),
		repositoryPath("capabilities", "infrastructure", "opentofu", "v2", "pack.json"),
		repositoryPath("capabilities", "security", "cosign", "v1", "pack.json"),
	} {
		if _, err := os.Stat(descriptor); err != nil {
			t.Fatalf("missing shipped capability pack descriptor %q: %v", descriptor, err)
		}
	}
}

// TestOpenTofuPackV2BindsTheValueEvaluatedProof proves the opentofu pack's
// major version 2: it ships as a new major beside the untouched v1 (a gate
// content change is never an in-place edit), it carries the value-evaluated
// custom-condition proof gate, and the conformance harness registers the
// shipped v2 descriptor.
func TestOpenTofuPackV2BindsTheValueEvaluatedProof(t *testing.T) {
	type packGate struct {
		Name  string   `json:"name"`
		Args  []string `json:"args"`
		Scope string   `json:"scope"`
	}
	type packDocument struct {
		Version int        `json:"version"`
		Gates   []packGate `json:"gates"`
	}
	readPack := func(path string) packDocument {
		t.Helper()
		var document packDocument
		if err := json.Unmarshal([]byte(readRepositoryFile(t, path)), &document); err != nil {
			t.Fatalf("%s is not valid JSON: %v", path, err)
		}
		return document
	}

	v1 := readPack(filepath.Join("capabilities", "infrastructure", "opentofu", "v1", "pack.json"))
	if v1.Version != 1 {
		t.Fatalf("the v1 descriptor carries version %d, want 1", v1.Version)
	}
	for _, gate := range v1.Gates {
		if gate.Name == "opentofu-test" {
			t.Fatal("the v1 descriptor must not carry the value-evaluated proof gate: a gate content change is never an in-place edit")
		}
	}

	v2 := readPack(filepath.Join("capabilities", "infrastructure", "opentofu", "v2", "pack.json"))
	if v2.Version != 2 {
		t.Fatalf("the v2 descriptor carries version %d, want 2", v2.Version)
	}
	wantGates := map[string]packGate{
		"opentofu-fmt-check": {Args: []string{"fmt", "-check", "-recursive"}, Scope: "repository"},
		"opentofu-init":      {Args: []string{"init", "-backend=false", "-input=false", "-no-color"}, Scope: "per-root"},
		"opentofu-validate":  {Args: []string{"validate", "-no-color"}, Scope: "per-root"},
		"opentofu-test":      {Args: []string{"test", "-no-color"}, Scope: "per-root"},
	}
	if len(v2.Gates) != len(wantGates) {
		t.Fatalf("the v2 descriptor carries %d gates, want %d", len(v2.Gates), len(wantGates))
	}
	for _, gate := range v2.Gates {
		want, found := wantGates[gate.Name]
		if !found {
			t.Fatalf("the v2 descriptor carries an unexpected gate %q", gate.Name)
		}
		if !slices.Equal(gate.Args, want.Args) || gate.Scope != want.Scope {
			t.Fatalf("the v2 gate %q carries %v/%s, want %v/%s", gate.Name, gate.Args, gate.Scope, want.Args, want.Scope)
		}
	}

	harness := readRepositoryFile(t, filepath.Join("cmd", "check-conformance", "main.go"))
	if !strings.Contains(harness, "capabilities/infrastructure/opentofu/v2/pack.json") {
		t.Fatal("the conformance harness does not register the shipped v2 descriptor")
	}

	readme := readRepositoryFile(t, filepath.Join("capabilities", "infrastructure", "opentofu", "README.md"))
	for _, required := range []string{
		"opentofu@2",
		"opentofu-test",
		"DEVELOPER_PLATFORM_INFRASTRUCTURE_AS_CODE_OPENTOFU_QUALITY_GATES_REFERENCE_001",
		"clean staging",
		"static evaluation-safety guard",
		"governed window",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("the pack README does not document %q", required)
		}
	}
}

// TestOpenTofuPacksDeclareTheEngineFloor proves that both shipped opentofu
// pack majors declare the minimum engine machinery their gates require: the
// clean-staging execution environment and the controlled gate environment are
// engine machinery, and a tenant whose pinned engine predates the declared
// level — or carries no compatibility proof entry for the pack major — fails
// closed at gate-plan resolution. The guard pins the declared form (a pinned
// three-part engine version), never the concrete floor value: the floor is
// instance data that rises with future machinery.
func TestOpenTofuPacksDeclareTheEngineFloor(t *testing.T) {
	type packDocument struct {
		Version          int    `json:"version"`
		MinEngineVersion string `json:"minEngineVersion"`
	}
	floorPattern := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	for _, descriptor := range []string{
		"capabilities/infrastructure/opentofu/v1/pack.json",
		"capabilities/infrastructure/opentofu/v2/pack.json",
	} {
		var document packDocument
		if err := json.Unmarshal([]byte(readRepositoryFile(t, descriptor)), &document); err != nil {
			t.Fatalf("%s is not valid JSON: %v", descriptor, err)
		}
		if !floorPattern.MatchString(document.MinEngineVersion) {
			t.Fatalf("%s carries minEngineVersion %q, want a pinned three-part engine version", descriptor, document.MinEngineVersion)
		}
	}

	schema := readRepositoryFile(t, filepath.Join("schemas", "capability-pack", "v1", "capability-pack.schema.json"))
	if !strings.Contains(schema, `"minEngineVersion"`) {
		t.Fatal("the capability-pack/v1 schema does not carry the minEngineVersion surface")
	}
}

func TestJSONSchemasStayInSyncWithValidators(t *testing.T) {
	documentSchema := readRepositoryFile(t, filepath.Join("schemas", "evidence-graph", "v1", "document.schema.json"))
	for _, required := range []string{
		"evidence-graph/v1",
		"source", "dependency-resolution", "build", "artifact", "promotion", "deployment", "operation",
		"resolves", "built-from", "produces", "attests", "promotes", "deploys", "revalidates", "revokes", "supersedes", "quarantines",
		"not-recorded", "pending", "verified", "failed", "revoked", "quarantined", "superseded",
		"sbom", "signature", "provenance", "attestation", "test", "scan", "approval", "exception", "policy", "quality", "revocation",
		"sha256:",
	} {
		if !strings.Contains(documentSchema, required) {
			t.Fatalf("document.schema.json does not contain %q", required)
		}
	}

	policySchema := readRepositoryFile(t, filepath.Join("schemas", "dependency-policy", "v1", "policy.schema.json"))
	for _, required := range []string{
		"dependency-policy/v1", "go", "npm", "python", "required_evidence", "download_block",
	} {
		if !strings.Contains(policySchema, required) {
			t.Fatalf("policy.schema.json does not contain %q", required)
		}
	}

	packSchema := readRepositoryFile(t, filepath.Join("schemas", "capability-pack", "v1", "capability-pack.schema.json"))
	for _, required := range []string{
		"capability-pack/v1", "provisioning", "recipe", "artifacts", "sha256", "signature",
		"discovery", "fileGlob", "assertions", "gates", "repository", "per-root", "minEngineVersion",
	} {
		if !strings.Contains(packSchema, required) {
			t.Fatalf("capability-pack.schema.json does not contain %q", required)
		}
	}

	configSchema := readRepositoryFile(t, filepath.Join("schemas", "quality-gate-config", "v4", "quality-gate-config.schema.json"))
	for _, required := range []string{
		"quality-gate-config/v4", `"const": 4`, "language", "version", "extends",
		"^[a-z0-9][a-z0-9-]*@[0-9]+$", "gates", "project", "scratch",
		`"default": ["feature", "fix", "docs", "refactor", "chore", "test", "perf", "hotfix"]`,
	} {
		if !strings.Contains(configSchema, required) {
			t.Fatalf("quality-gate-config.schema.json does not contain %q", required)
		}
	}
}

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(repositoryPath(filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return string(content)
}

func repositoryPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}
