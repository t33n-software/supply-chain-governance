package capabilitypack

import (
	"strings"
	"testing"
)

var validDescriptor = `{
  "schema": "capability-pack/v1",
  "capability": "opentofu",
  "area": "infrastructure",
  "version": 1,
  "summary": "OpenTofu infrastructure gates.",
  "provisioning": {
    "kind": "recipe",
    "tool": "tofu",
    "version": "1.12.5",
    "environment": {"OPENTOFU_ENFORCE_GPG_VALIDATION": "true"},
    "artifacts": {
      "linux-amd64": {
        "url": "https://example.invalid/tofu_1.12.5_linux_amd64.zip",
        "sha256": "` + strings.Repeat("a", 64) + `",
        "signature": "https://example.invalid/tofu_1.12.5_linux_amd64.zip.sig"
      }
    }
  },
  "discovery": {
    "roots": {"fileGlob": "**/*.tf"},
    "excludeDirs": [".terraform", "dist"]
  },
  "assertions": [
    {"name": "opentofu-version", "command": "tofu", "args": ["version"], "expect": "OpenTofu v1.12.5"}
  ],
  "gates": [
    {"name": "opentofu-fmt-check", "command": "tofu", "args": ["fmt", "-check", "-recursive"], "scope": "repository"},
    {"name": "opentofu-validate", "command": "tofu", "args": ["validate", "-no-color"], "scope": "per-root", "timeout": "5m"}
  ]
}`

func mutate(t *testing.T, old, replacement string) string {
	t.Helper()
	if !strings.Contains(validDescriptor, old) {
		t.Fatalf("the valid descriptor does not contain %q", old)
	}
	return strings.Replace(validDescriptor, old, replacement, 1)
}

func TestParseAcceptsTheValidDescriptor(t *testing.T) {
	t.Parallel()

	descriptor, err := Parse([]byte(validDescriptor))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if descriptor.Capability != "opentofu" ||
		descriptor.Area != "infrastructure" ||
		descriptor.Version != 1 ||
		descriptor.Provisioning.Tool != "tofu" ||
		descriptor.Provisioning.Artifacts["linux-amd64"].Signature == "" ||
		descriptor.Discovery.Roots.FileGlob != "**/*.tf" ||
		len(descriptor.Assertions) != 1 ||
		len(descriptor.Gates) != 2 ||
		descriptor.Gates[1].Timeout != "5m" {
		t.Fatalf("Parse() = %#v", descriptor)
	}
}

// The bootstrap form of the engine-bound signature verifier pack: the
// install-proof assertion without the gates and discovery surfaces.
var validBootstrapDescriptor = `{
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
      "linux-amd64": {
        "url": "https://example.invalid/cosign-linux-amd64",
        "sha256": "` + strings.Repeat("b", 64) + `"
      }
    }
  },
  "assertions": [
    {"name": "cosign-version", "command": "cosign", "args": ["version"], "expect": "v3.0.6"}
  ]
}`

func TestParseAcceptsTheBootstrapVerifierForm(t *testing.T) {
	t.Parallel()

	descriptor, err := Parse([]byte(validBootstrapDescriptor))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if descriptor.Gates != nil || descriptor.Discovery != nil {
		t.Fatalf("Parse() = %#v, want the bootstrap form without the gates and discovery surfaces", descriptor)
	}
	if len(descriptor.Assertions) != 1 || descriptor.Assertions[0].Name != "cosign-version" {
		t.Fatalf("Parse() assertions = %#v", descriptor.Assertions)
	}
}

func TestParseAcceptsTheEngineMachineryBinding(t *testing.T) {
	t.Parallel()

	descriptor, err := Parse([]byte(mutate(t, `"summary": "OpenTofu infrastructure gates."`, `"summary": "OpenTofu infrastructure gates.", "minEngineVersion": "1.1.0"`)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if descriptor.MinEngineVersion != "1.1.0" {
		t.Fatalf("Parse() minEngineVersion = %q, want %q", descriptor.MinEngineVersion, "1.1.0")
	}
}

func TestParseAcceptsRepositoryScopeGatesWithoutDiscovery(t *testing.T) {
	t.Parallel()

	contents := `{
  "schema": "capability-pack/v1",
  "capability": "cosign",
  "area": "security",
  "version": 1,
  "summary": "A repository-scope gate needs no discovery surface.",
  "provisioning": {
    "kind": "recipe",
    "tool": "cosign",
    "version": "3.0.6",
    "environment": {},
    "artifacts": {
      "linux-amd64": {
        "url": "https://example.invalid/cosign-linux-amd64",
        "sha256": "` + strings.Repeat("b", 64) + `"
      }
    }
  },
  "assertions": [],
  "gates": [
    {"name": "cosign-verify", "command": "cosign", "args": ["verify"], "scope": "repository"}
  ]
}`
	descriptor, err := Parse([]byte(contents))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if descriptor.Discovery != nil || len(descriptor.Gates) != 1 {
		t.Fatalf("Parse() = %#v", descriptor)
	}
}

func TestParseRejectsNonConformingDocuments(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		contents string
		want     string
	}{
		{
			name:     "forbidden content",
			contents: strings.Replace(validDescriptor, `"summary": "OpenTofu infrastructure gates."`, `"summary": "-----BEGIN RSA PRIVATE KEY-----`, 1),
			want:     "forbidden credential-like content",
		},
		{
			name:     "invalid json",
			contents: `{`,
			want:     "decode capability pack descriptor",
		},
		{
			name:     "unknown field",
			contents: mutate(t, `"summary":`, `"unknown": true, "summary":`),
			want:     "decode capability pack descriptor",
		},
		{
			name:     "trailing data",
			contents: validDescriptor + " {}",
			want:     "trailing data",
		},
		{
			name:     "wrong schema identity",
			contents: mutate(t, `"capability-pack/v1"`, `"capability-pack/v2"`),
			want:     `schema must be "capability-pack/v1"`,
		},
		{
			name:     "non-integer version",
			contents: mutate(t, `"version": 1,`, `"version": 1.5,`),
			want:     "decode capability pack descriptor",
		},
		{
			name:     "capability not kebab",
			contents: mutate(t, `"capability": "opentofu"`, `"capability": "OpenTofu"`),
			want:     "capability",
		},
		{
			name:     "area not kebab",
			contents: mutate(t, `"area": "infrastructure"`, `"area": "Infra"`),
			want:     "area",
		},
		{
			name:     "version below one",
			contents: mutate(t, `"version": 1,`, `"version": 0,`),
			want:     "version must be a positive major version",
		},
		{
			name:     "engine floor two-part",
			contents: mutate(t, `"version": 1,`, `"version": 1, "minEngineVersion": "1.2",`),
			want:     "must be a pinned three-part engine version",
		},
		{
			name:     "engine floor unpinned",
			contents: mutate(t, `"version": 1,`, `"version": 1, "minEngineVersion": "latest",`),
			want:     "must be a pinned three-part engine version",
		},
		{
			name:     "empty summary",
			contents: mutate(t, `"summary": "OpenTofu infrastructure gates."`, `"summary": " "`),
			want:     "summary must not be empty",
		},
		{
			name:     "provisioning kind",
			contents: mutate(t, `"kind": "recipe"`, `"kind": "image"`),
			want:     `kind must be "recipe"`,
		},
		{
			name:     "provisioning tool",
			contents: mutate(t, `"tool": "tofu"`, `"tool": "OpenTofu"`),
			want:     "tool",
		},
		{
			name:     "provisioning version unpinned",
			contents: mutate(t, `"version": "1.12.5"`, `"version": "latest"`),
			want:     "must be a pinned version",
		},
		{
			name:     "environment key form",
			contents: mutate(t, `"OPENTOFU_ENFORCE_GPG_VALIDATION"`, `"opentofu_enforce"`),
			want:     "environment key",
		},
		{
			name:     "environment value control",
			contents: "{\"schema\": \"capability-pack/v1\", \"capability\": \"opentofu\", \"area\": \"infrastructure\", \"version\": 1, \"summary\": \"x\", \"provisioning\": {\"kind\": \"recipe\", \"tool\": \"tofu\", \"version\": \"1.12.5\", \"environment\": {\"OPENTOFU_ENFORCE_GPG_VALIDATION\": \"tr\\nue\"}, \"artifacts\": {\"linux-amd64\": {\"url\": \"https://example.invalid/x.zip\", \"sha256\": \"" + strings.Repeat("a", 64) + "\"}}}, \"discovery\": {\"roots\": {\"fileGlob\": \"**/*.tf\"}, \"excludeDirs\": []}, \"assertions\": [], \"gates\": [{\"name\": \"opentofu-fmt-check\", \"command\": \"tofu\", \"args\": [], \"scope\": \"repository\"}]}",
			want:     "environment",
		},
		{
			name: "no artifacts",
			contents: mutate(t, `"artifacts": {
      "linux-amd64": {
        "url": "https://example.invalid/tofu_1.12.5_linux_amd64.zip",
        "sha256": "`+strings.Repeat("a", 64)+`",
        "signature": "https://example.invalid/tofu_1.12.5_linux_amd64.zip.sig"
      }
    }`, `"artifacts": {}`),
			want: "artifacts must bind at least one platform",
		},
		{
			name:     "artifact platform key",
			contents: mutate(t, `"linux-amd64":`, `"linux":`),
			want:     "<goos>-<goarch>",
		},
		{
			name:     "artifact url not https",
			contents: mutate(t, `"url": "https://example.invalid/tofu_1.12.5_linux_amd64.zip"`, `"url": "http://example.invalid/tofu_1.12.5_linux_amd64.zip"`),
			want:     "must use https",
		},
		{
			name:     "artifact digest malformed",
			contents: mutate(t, strings.Repeat("a", 64), strings.Repeat("A", 64)),
			want:     "sha256 must be 64 lowercase hex characters",
		},
		{
			name:     "discovery empty glob",
			contents: mutate(t, `"fileGlob": "**/*.tf"`, `"fileGlob": " "`),
			want:     "roots.fileGlob",
		},
		{
			name: "discovery present but empty",
			contents: mutate(t, `"discovery": {
    "roots": {"fileGlob": "**/*.tf"},
    "excludeDirs": [".terraform", "dist"]
  }`, `"discovery": {}`),
			want: "roots.fileGlob",
		},
		{
			name: "per-root gate without discovery",
			contents: mutate(t, `  "discovery": {
    "roots": {"fileGlob": "**/*.tf"},
    "excludeDirs": [".terraform", "dist"]
  },
`, ""),
			want: "per-root scope requires the discovery surface",
		},
		{
			name:     "discovery duplicate exclude",
			contents: mutate(t, `"excludeDirs": [".terraform", "dist"]`, `"excludeDirs": ["dist", "dist"]`),
			want:     "not unique",
		},
		{
			name:     "discovery empty exclude",
			contents: mutate(t, `"excludeDirs": [".terraform", "dist"]`, `"excludeDirs": [".terraform", " "]`),
			want:     "excludeDirs[1]",
		},
		{
			name:     "assertion name form",
			contents: mutate(t, `"name": "opentofu-version"`, `"name": "OpenTofu"`),
			want:     "assertion name",
		},
		{
			name:     "assertion empty expect",
			contents: mutate(t, `"expect": "OpenTofu v1.12.5"`, `"expect": ""`),
			want:     "expect must not be empty",
		},
		{
			name: "gates empty",
			contents: mutate(t, `"gates": [
    {"name": "opentofu-fmt-check", "command": "tofu", "args": ["fmt", "-check", "-recursive"], "scope": "repository"},
    {"name": "opentofu-validate", "command": "tofu", "args": ["validate", "-no-color"], "scope": "per-root", "timeout": "5m"}
  ]`, `"gates": []`),
			want: "gates must not be empty",
		},
		{
			name:     "gate name form",
			contents: mutate(t, `"name": "opentofu-fmt-check"`, `"name": "opentofu_fmt"`),
			want:     "gate name",
		},
		{
			name:     "gate name without capability prefix",
			contents: mutate(t, `"name": "opentofu-fmt-check"`, `"name": "tofu-fmt-check"`),
			want:     "must be prefixed by the capability",
		},
		{
			name:     "gate scope",
			contents: mutate(t, `"scope": "repository"`, `"scope": "global"`),
			want:     "scope",
		},
		{
			name:     "gate timeout not a duration",
			contents: mutate(t, `"timeout": "5m"`, `"timeout": "abc"`),
			want:     "positive Go duration",
		},
		{
			name:     "gate timeout negative",
			contents: mutate(t, `"timeout": "5m"`, `"timeout": "-5m"`),
			want:     "positive Go duration",
		},
		{
			name:     "duplicate gate names",
			contents: mutate(t, `"name": "opentofu-validate", "command": "tofu", "args": ["validate", "-no-color"], "scope": "per-root", "timeout": "5m"`, `"name": "opentofu-fmt-check", "command": "tofu", "args": ["validate"], "scope": "per-root"`),
			want:     "not unique",
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePack([]byte(testCase.contents))
			if err == nil {
				t.Fatalf("ValidatePack() = nil, want %q", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("ValidatePack() error = %q, want substring %q", err.Error(), testCase.want)
			}
		})
	}
}

func TestDescriptorValidationBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("artifact url control characters", func(t *testing.T) {
		t.Parallel()
		artifact := Artifact{URL: "https://example.invalid/x\n.zip", SHA256: strings.Repeat("a", 64)}
		if err := artifact.validate("linux-amd64"); err == nil || !strings.Contains(err.Error(), "control characters") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("artifact signature control characters", func(t *testing.T) {
		t.Parallel()
		artifact := Artifact{URL: "https://example.invalid/x.zip", SHA256: strings.Repeat("a", 64), Signature: "sig\nref"}
		if err := artifact.validate("linux-amd64"); err == nil || !strings.Contains(err.Error(), "control characters") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("artifact without signature is valid", func(t *testing.T) {
		t.Parallel()
		artifact := Artifact{URL: "https://example.invalid/x.zip", SHA256: strings.Repeat("a", 64)}
		if err := artifact.validate("linux-amd64"); err != nil {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("discovery glob control characters", func(t *testing.T) {
		t.Parallel()
		discovery := Discovery{Roots: Roots{FileGlob: "**/*\n.tf"}}
		if err := discovery.validate(); err == nil || !strings.Contains(err.Error(), "fileGlob") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("assertion command empty", func(t *testing.T) {
		t.Parallel()
		assertion := Assertion{Name: "ok", Command: " ", Expect: "x"}
		if err := assertion.validate(); err == nil || !strings.Contains(err.Error(), "command") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("assertion argument control characters", func(t *testing.T) {
		t.Parallel()
		assertion := Assertion{Name: "ok", Command: "tool", Args: []string{"a\nb"}, Expect: "x"}
		if err := assertion.validate(); err == nil || !strings.Contains(err.Error(), "args[0]") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("gate command empty", func(t *testing.T) {
		t.Parallel()
		gate := Gate{Name: "opentofu-fmt-check", Command: " ", Scope: ScopeRepository}
		if err := gate.validate("opentofu"); err == nil || !strings.Contains(err.Error(), "command") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("gate argument control characters", func(t *testing.T) {
		t.Parallel()
		gate := Gate{Name: "opentofu-fmt-check", Command: "tofu", Args: []string{"fmt\n"}, Scope: ScopeRepository}
		if err := gate.validate("opentofu"); err == nil || !strings.Contains(err.Error(), "args[0]") {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("gate without timeout is valid", func(t *testing.T) {
		t.Parallel()
		gate := Gate{Name: "opentofu-fmt-check", Command: "tofu", Scope: ScopeRepository}
		if err := gate.validate("opentofu"); err != nil {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("provisioning without environment is valid", func(t *testing.T) {
		t.Parallel()
		provisioning := Provisioning{
			Kind:    ProvisioningRecipe,
			Tool:    "tofu",
			Version: "1.12.5",
			Artifacts: map[string]Artifact{
				"linux-amd64": {URL: "https://example.invalid/x.zip", SHA256: strings.Repeat("a", 64)},
			},
		}
		if err := provisioning.validate(); err != nil {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("discovery without excludes is valid", func(t *testing.T) {
		t.Parallel()
		discovery := Discovery{Roots: Roots{FileGlob: "**/*.tf"}}
		if err := discovery.validate(); err != nil {
			t.Fatalf("validate() = %v", err)
		}
	})

	t.Run("descriptor with a malformed engine floor", func(t *testing.T) {
		t.Parallel()
		descriptor := Descriptor{
			Schema:           SchemaID,
			Capability:       "opentofu",
			Area:             "infrastructure",
			Version:          1,
			Summary:          "x",
			MinEngineVersion: "1.2",
		}
		if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "minEngineVersion") {
			t.Fatalf("Validate() = %v", err)
		}
	})
}
