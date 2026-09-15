package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	testDigestA = strings.Repeat("a", 64)
	testDigestB = strings.Repeat("b", 64)
	testDigestC = strings.Repeat("c", 64)
)

var validVectorDocument = `{
  "schema": "evidence-graph/v1",
  "document": {"id": "doc-1", "type": "subject-document", "issuer": "issuer-1", "created_at": "2026-08-12T00:00:00Z"},
  "subject": {"id": "sub-1", "type": "artifact", "primary_digest": "sha256:` + testDigestA + `"},
  "relations": [],
  "evidence": [],
  "policy": {"bundle": "bundle-1", "decision": "allow"},
  "lifecycle": {"status": "pending"},
  "integrity": {"canonical_payload_digest": "sha256:` + testDigestB + `", "signature": {"issuer": "issuer-1", "reference": "ref-1", "digest": "sha256:` + testDigestC + `"}}
}`

var validPolicyDocument = `{
  "schema": "dependency-policy/v1",
  "ecosystem": "go",
  "admission": {"required_evidence": ["sbom"]},
  "exceptions": [],
  "revocation": {"download_block": true}
}`

var validPackDescriptor = `{
  "schema": "capability-pack/v1",
  "capability": "opentofu",
  "area": "infrastructure",
  "version": 1,
  "summary": "OpenTofu infrastructure gates.",
  "provisioning": {
    "kind": "recipe",
    "tool": "tofu",
    "version": "1.12.5",
    "environment": {},
    "artifacts": {
      "linux-amd64": {"url": "https://example.invalid/tofu.zip", "sha256": "` + testDigestA + `"}
    }
  },
  "discovery": {"roots": {"fileGlob": "**/*.tf"}, "excludeDirs": []},
  "assertions": [],
  "gates": [
    {"name": "opentofu-validate", "command": "tofu", "args": ["validate"], "scope": "per-root"}
  ]
}`

var validBootstrapPackDescriptor = `{
  "schema": "capability-pack/v1",
  "capability": "cosign",
  "area": "security",
  "version": 1,
  "summary": "Signature verifier bootstrap.",
  "provisioning": {
    "kind": "recipe",
    "tool": "cosign",
    "version": "3.0.6",
    "environment": {},
    "artifacts": {
      "linux-amd64": {"url": "https://example.invalid/cosign-linux-amd64", "sha256": "` + testDigestB + `"}
    }
  },
  "assertions": [
    {"name": "cosign-version", "command": "cosign", "args": ["version"], "expect": "v3.0.6"}
  ]
}`

var validPackV2Descriptor = `{
  "schema": "capability-pack/v1",
  "capability": "opentofu",
  "area": "infrastructure",
  "version": 2,
  "summary": "OpenTofu infrastructure gates with the value-evaluated proof.",
  "provisioning": {
    "kind": "recipe",
    "tool": "tofu",
    "version": "1.12.5",
    "environment": {},
    "artifacts": {
      "linux-amd64": {"url": "https://example.invalid/tofu.zip", "sha256": "` + testDigestA + `"}
    }
  },
  "discovery": {"roots": {"fileGlob": "**/*.tf"}, "excludeDirs": []},
  "assertions": [],
  "gates": [
    {"name": "opentofu-validate", "command": "tofu", "args": ["validate"], "scope": "per-root"},
    {"name": "opentofu-test", "command": "tofu", "args": ["test"], "scope": "per-root"}
  ]
}`

var validConfigDocument = `{
  "schemaVersion": 4,
  "toolchain": {"language": "go", "version": "1.26.6"},
  "gates": [
    {"name": "full-local-build", "command": "go", "args": ["tool", "-modfile", "tools/go.mod", "quality-gate"], "timeout": "15m"}
  ]
}`

func restoreSeams(t *testing.T) {
	t.Helper()
	originalExit := exitProcess
	originalArgs := commandArgs
	originalRoot := vectorRoot
	t.Cleanup(func() {
		exitProcess = originalExit
		commandArgs = originalArgs
		vectorRoot = originalRoot
	})
}

func writeFile(t *testing.T, root string, name string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeConfigVectors(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, "schemas/quality-gate-config/conformance/positive/ok.json", validConfigDocument)
	writeFile(t, root, "schemas/quality-gate-config/conformance/negative/bad.json", `{"schemaVersion": 3}`)
}

func validVectorRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "schemas/evidence-graph/conformance/positive/ok.json", validVectorDocument)
	writeFile(t, root, "schemas/evidence-graph/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "conformance/positive/ok.json", validPolicyDocument)
	writeFile(t, root, "conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/positive/ok.json", validPackDescriptor)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/security/cosign/conformance/positive/ok.json", validBootstrapPackDescriptor)
	writeFile(t, root, "capabilities/security/cosign/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeConfigVectors(t, root)
	writeFile(t, root, "capabilities/infrastructure/opentofu/v1/pack.json", validPackDescriptor)
	writeFile(t, root, "capabilities/infrastructure/opentofu/v2/pack.json", validPackV2Descriptor)
	writeFile(t, root, "capabilities/security/cosign/v1/pack.json", validBootstrapPackDescriptor)
	for _, ecosystem := range []string{"go", "npm", "python"} {
		writeFile(t, root, "policies/dependency/"+ecosystem+"/policy.json", validPolicyDocument)
	}
	return root
}

func TestMainExitsWithRunResult(t *testing.T) {
	restoreSeams(t)
	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	commandArgs = []string{"check-conformance"}
	vectorRoot = validVectorRoot(t)

	main()

	if exitCode != 0 {
		t.Fatalf("main() exit code = %d, want 0", exitCode)
	}
}

func TestMainRejectsArguments(t *testing.T) {
	restoreSeams(t)
	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	commandArgs = []string{"check-conformance", "unexpected"}
	vectorRoot = validVectorRoot(t)

	main()

	if exitCode != 2 {
		t.Fatalf("main() exit code = %d, want 2", exitCode)
	}
}

func TestRunPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, t.TempDir(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if stdout.String() != "check-conformance devel\n" {
		t.Fatalf("stdout = %q, want version output", stdout.String())
	}
}

func TestRunFailsWhenVectorSetFails(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "schemas/evidence-graph/conformance/positive/ok.json", validVectorDocument)
	writeFile(t, root, "schemas/evidence-graph/conformance/negative/.keep", "")
	writeFile(t, root, "conformance/positive/ok.json", validPolicyDocument)
	writeFile(t, root, "conformance/negative/bad.json", `{"schema": "nope"}`)
	for _, ecosystem := range []string{"go", "npm", "python"} {
		writeFile(t, root, "policies/dependency/"+ecosystem+"/policy.json", validPolicyDocument)
	}

	var stdout, stderr bytes.Buffer
	code := run(nil, root, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "no JSON vectors") {
		t.Fatalf("stderr = %q, want empty vector directory error", stderr.String())
	}
}

func TestRunFailsWhenShippedPolicyIsMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "schemas/evidence-graph/conformance/positive/ok.json", validVectorDocument)
	writeFile(t, root, "schemas/evidence-graph/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "conformance/positive/ok.json", validPolicyDocument)
	writeFile(t, root, "conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/positive/ok.json", validPackDescriptor)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/security/cosign/conformance/positive/ok.json", validBootstrapPackDescriptor)
	writeFile(t, root, "capabilities/security/cosign/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeConfigVectors(t, root)

	var stdout, stderr bytes.Buffer
	code := run(nil, root, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read shipped policy") {
		t.Fatalf("stderr = %q, want shipped policy read error", stderr.String())
	}
}

func TestRunFailsWhenShippedPolicyIsInvalid(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "schemas/evidence-graph/conformance/positive/ok.json", validVectorDocument)
	writeFile(t, root, "schemas/evidence-graph/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "conformance/positive/ok.json", validPolicyDocument)
	writeFile(t, root, "conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/positive/ok.json", validPackDescriptor)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/security/cosign/conformance/positive/ok.json", validBootstrapPackDescriptor)
	writeFile(t, root, "capabilities/security/cosign/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeConfigVectors(t, root)
	writeFile(t, root, "policies/dependency/go/policy.json", `{"schema": "nope"}`)
	writeFile(t, root, "policies/dependency/npm/policy.json", validPolicyDocument)
	writeFile(t, root, "policies/dependency/python/policy.json", validPolicyDocument)

	var stdout, stderr bytes.Buffer
	code := run(nil, root, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "not conformant") {
		t.Fatalf("stderr = %q, want shipped policy conformance error", stderr.String())
	}
}

func TestRunFailsWhenShippedPackIsMissing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "schemas/evidence-graph/conformance/positive/ok.json", validVectorDocument)
	writeFile(t, root, "schemas/evidence-graph/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "conformance/positive/ok.json", validPolicyDocument)
	writeFile(t, root, "conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/positive/ok.json", validPackDescriptor)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/security/cosign/conformance/positive/ok.json", validBootstrapPackDescriptor)
	writeFile(t, root, "capabilities/security/cosign/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeConfigVectors(t, root)
	for _, ecosystem := range []string{"go", "npm", "python"} {
		writeFile(t, root, "policies/dependency/"+ecosystem+"/policy.json", validPolicyDocument)
	}

	var stdout, stderr bytes.Buffer
	code := run(nil, root, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read shipped capability pack") {
		t.Fatalf("stderr = %q, want shipped pack read error", stderr.String())
	}
}

func TestRunFailsWhenShippedPackIsInvalid(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "schemas/evidence-graph/conformance/positive/ok.json", validVectorDocument)
	writeFile(t, root, "schemas/evidence-graph/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "conformance/positive/ok.json", validPolicyDocument)
	writeFile(t, root, "conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/positive/ok.json", validPackDescriptor)
	writeFile(t, root, "capabilities/infrastructure/opentofu/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeFile(t, root, "capabilities/security/cosign/conformance/positive/ok.json", validBootstrapPackDescriptor)
	writeFile(t, root, "capabilities/security/cosign/conformance/negative/bad.json", `{"schema": "nope"}`)
	writeConfigVectors(t, root)
	writeFile(t, root, "capabilities/infrastructure/opentofu/v1/pack.json", `{"schema": "nope"}`)
	for _, ecosystem := range []string{"go", "npm", "python"} {
		writeFile(t, root, "policies/dependency/"+ecosystem+"/policy.json", validPolicyDocument)
	}

	var stdout, stderr bytes.Buffer
	code := run(nil, root, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "shipped capability pack") || !strings.Contains(stderr.String(), "not conformant") {
		t.Fatalf("stderr = %q, want shipped pack conformance error", stderr.String())
	}
}

func TestRunSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, validVectorRoot(t), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "conformant") {
		t.Fatalf("stdout = %q, want success message", stdout.String())
	}
}
