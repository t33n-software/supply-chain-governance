// Command check-conformance runs every conformance vector set and validates
// the shipped dependency policies and capability pack descriptors.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/t33n-software/supply-chain-governance/internal/capabilitypack"
	"github.com/t33n-software/supply-chain-governance/internal/dependencypolicy"
	"github.com/t33n-software/supply-chain-governance/internal/evidencegraph"
	"github.com/t33n-software/supply-chain-governance/internal/qualitygateconfig"
)

var (
	exitProcess = os.Exit
	commandArgs = os.Args
	vectorRoot  = "."
	version     = "devel"
)

func main() {
	exitProcess(run(commandArgs[1:], vectorRoot, os.Stdout, os.Stderr))
}

type vectorSet struct {
	name        string
	directory   string
	expectValid bool
	parse       evidencegraph.ParseFunc
}

func conformanceSets() []vectorSet {
	return []vectorSet{
		{
			name:        "evidence-graph positive vectors",
			directory:   "schemas/evidence-graph/conformance/positive",
			expectValid: true,
			parse:       evidencegraph.ValidateDocument,
		},
		{
			name:        "evidence-graph negative vectors",
			directory:   "schemas/evidence-graph/conformance/negative",
			expectValid: false,
			parse:       evidencegraph.ValidateDocument,
		},
		{
			name:        "dependency-policy positive vectors",
			directory:   "conformance/positive",
			expectValid: true,
			parse:       dependencypolicy.ValidatePolicy,
		},
		{
			name:        "dependency-policy negative vectors",
			directory:   "conformance/negative",
			expectValid: false,
			parse:       dependencypolicy.ValidatePolicy,
		},
		{
			name:        "capability-pack opentofu positive vectors",
			directory:   "capabilities/infrastructure/opentofu/conformance/positive",
			expectValid: true,
			parse:       capabilitypack.ValidatePack,
		},
		{
			name:        "capability-pack opentofu negative vectors",
			directory:   "capabilities/infrastructure/opentofu/conformance/negative",
			expectValid: false,
			parse:       capabilitypack.ValidatePack,
		},
		{
			name:        "capability-pack cosign positive vectors",
			directory:   "capabilities/security/cosign/conformance/positive",
			expectValid: true,
			parse:       capabilitypack.ValidatePack,
		},
		{
			name:        "capability-pack cosign negative vectors",
			directory:   "capabilities/security/cosign/conformance/negative",
			expectValid: false,
			parse:       capabilitypack.ValidatePack,
		},
		{
			name:        "quality-gate-config positive vectors",
			directory:   "schemas/quality-gate-config/conformance/positive",
			expectValid: true,
			parse:       qualitygateconfig.ValidateConfig,
		},
		{
			name:        "quality-gate-config negative vectors",
			directory:   "schemas/quality-gate-config/conformance/negative",
			expectValid: false,
			parse:       qualitygateconfig.ValidateConfig,
		},
	}
}

func shippedPolicyEcosystems() []string {
	return []string{"go", "npm", "python"}
}

func shippedPackDescriptors() []string {
	return []string{
		"capabilities/infrastructure/opentofu/v1/pack.json",
		"capabilities/infrastructure/opentofu/v2/pack.json",
		"capabilities/security/cosign/v1/pack.json",
	}
}

func run(arguments []string, root string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--version" {
		fmt.Fprintf(stdout, "check-conformance %s\n", version)
		return 0
	}
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "usage: check-conformance")
		return 2
	}
	fsys := os.DirFS(root)
	for _, set := range conformanceSets() {
		fmt.Fprintln(stdout, "==>", set.name)
		if err := evidencegraph.RunVectorSet(fsys, set.directory, set.expectValid, set.parse); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	for _, ecosystem := range shippedPolicyEcosystems() {
		name := "policies/dependency/" + ecosystem + "/policy.json"
		fmt.Fprintln(stdout, "==> shipped policy", name)
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			fmt.Fprintf(stderr, "read shipped policy %q: %v\n", name, err)
			return 1
		}
		if err := dependencypolicy.ValidatePolicy(data); err != nil {
			fmt.Fprintf(stderr, "shipped policy %q is not conformant: %v\n", name, err)
			return 1
		}
	}
	for _, name := range shippedPackDescriptors() {
		fmt.Fprintln(stdout, "==> shipped capability pack", name)
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			fmt.Fprintf(stderr, "read shipped capability pack %q: %v\n", name, err)
			return 1
		}
		if err := capabilitypack.ValidatePack(data); err != nil {
			fmt.Fprintf(stderr, "shipped capability pack %q is not conformant: %v\n", name, err)
			return 1
		}
	}
	fmt.Fprintln(stdout, "All conformance vectors, shipped policies, and shipped capability packs are conformant.")
	return 0
}
