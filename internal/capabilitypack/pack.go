// Package capabilitypack implements the capability-pack/v1 descriptor format
// used by the shared kernel's capability registry.
package capabilitypack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/t33n-software/supply-chain-governance/internal/evidencegraph"
)

// SchemaID is the canonical capability pack descriptor schema identifier.
const SchemaID = "capability-pack/v1"

// ProvisioningRecipe is the only provisioning kind: a bound recipe of
// digest-verified artifact downloads.
const ProvisioningRecipe = "recipe"

// Gate scopes: a repository gate runs once at the root; a per-root gate runs
// once per discovered root.
const (
	ScopeRepository = "repository"
	ScopePerRoot    = "per-root"
)

var (
	identityPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	toolPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	versionPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	engineVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	platformPattern      = regexp.MustCompile(`^[a-z0-9]+-[a-z0-9]+$`)
	environmentPattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	digestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Descriptor is one versioned capability pack descriptor. The discovery and
// gates surfaces are nil for the engine-bound signature verifier bootstrap
// pack, whose proof runs inside provisioning; every gate-carrying pack binds
// the gates, and a per-root gate never exists without the discovery surface.
type Descriptor struct {
	Schema       string       `json:"schema"`
	Capability   string       `json:"capability"`
	Area         string       `json:"area"`
	Version      int          `json:"version"`
	Summary      string       `json:"summary"`
	Provisioning Provisioning `json:"provisioning"`
	Discovery    *Discovery   `json:"discovery"`
	Assertions   []Assertion  `json:"assertions"`
	Gates        []Gate       `json:"gates"`
	// MinEngineVersion is the optional engine-machinery binding: the minimum
	// engine version whose machinery the pack's declared gates require,
	// including the execution environment they assume. When present, a tenant
	// whose pinned engine predates the declared level — or whose pinned engine
	// carries no compatibility proof entry for this pack major — fails closed
	// at gate-plan resolution: the pack's declared form never degrades into a
	// local re-implementation on an older engine and never executes unproven.
	MinEngineVersion string `json:"minEngineVersion,omitempty"`
}

// Provisioning binds the recipe by which a runner receives the pack's tool.
type Provisioning struct {
	Kind        string              `json:"kind"`
	Tool        string              `json:"tool"`
	Version     string              `json:"version"`
	Environment map[string]string   `json:"environment"`
	Artifacts   map[string]Artifact `json:"artifacts"`
}

// Artifact binds one platform's release artifact by URL and digest.
type Artifact struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature,omitempty"`
}

// Discovery binds how the pack finds its work.
type Discovery struct {
	Roots       Roots    `json:"roots"`
	ExcludeDirs []string `json:"excludeDirs"`
}

// Roots binds the file glob whose parent directories form the per-root set.
type Roots struct {
	FileGlob string `json:"fileGlob"`
}

// Assertion is a fail-closed environment proof executed before any pack gate.
type Assertion struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Expect  string   `json:"expect"`
}

// Gate is one pack gate step.
type Gate struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Scope   string   `json:"scope"`
	Timeout string   `json:"timeout,omitempty"`
}

// Parse decodes and validates one capability-pack/v1 descriptor. Unknown
// fields, trailing data, and credential-like content are rejected fail-closed.
func Parse(data []byte) (Descriptor, error) {
	var descriptor Descriptor
	if err := evidencegraph.RejectForbiddenContent(data); err != nil {
		return descriptor, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return descriptor, fmt.Errorf("decode capability pack descriptor: %w", err)
	}
	if decoder.More() {
		return descriptor, errors.New("capability pack descriptor contains trailing data")
	}
	if err := descriptor.Validate(); err != nil {
		return descriptor, err
	}
	return descriptor, nil
}

// ValidatePack parses and validates one capability-pack/v1 descriptor.
func ValidatePack(data []byte) error {
	_, err := Parse(data)
	return err
}

// Validate enforces every capability-pack/v1 invariant.
func (d Descriptor) Validate() error {
	if d.Schema != SchemaID {
		return fmt.Errorf("schema must be %q, got %q", SchemaID, d.Schema)
	}
	if !identityPattern.MatchString(d.Capability) {
		return fmt.Errorf("capability %q must be a lowercase kebab identifier", d.Capability)
	}
	if !identityPattern.MatchString(d.Area) {
		return fmt.Errorf("area %q must be a lowercase kebab identifier", d.Area)
	}
	if d.Version < 1 {
		return fmt.Errorf("version must be a positive major version, got %d", d.Version)
	}
	if d.MinEngineVersion != "" && !engineVersionPattern.MatchString(d.MinEngineVersion) {
		return fmt.Errorf("minEngineVersion %q must be a pinned three-part engine version such as 1.3.0", d.MinEngineVersion)
	}
	if strings.TrimSpace(d.Summary) == "" {
		return errors.New("summary must not be empty")
	}
	if err := d.Provisioning.validate(); err != nil {
		return fmt.Errorf("provisioning: %w", err)
	}
	if d.Discovery != nil {
		if err := d.Discovery.validate(); err != nil {
			return fmt.Errorf("discovery: %w", err)
		}
	}
	for index, assertion := range d.Assertions {
		if err := assertion.validate(); err != nil {
			return fmt.Errorf("assertions[%d]: %w", index, err)
		}
	}
	if d.Gates != nil && len(d.Gates) == 0 {
		return errors.New("gates must not be empty when the gates field is present")
	}
	seen := make(map[string]struct{}, len(d.Gates))
	for index, gate := range d.Gates {
		if err := gate.validate(d.Capability); err != nil {
			return fmt.Errorf("gates[%d]: %w", index, err)
		}
		if gate.Scope == ScopePerRoot && d.Discovery == nil {
			return fmt.Errorf("gates[%d]: the per-root scope requires the discovery surface", index)
		}
		if _, found := seen[gate.Name]; found {
			return fmt.Errorf("gates[%d]: gate name %q is not unique", index, gate.Name)
		}
		seen[gate.Name] = struct{}{}
	}
	return nil
}

func (p Provisioning) validate() error {
	if p.Kind != ProvisioningRecipe {
		return fmt.Errorf("kind must be %q, got %q", ProvisioningRecipe, p.Kind)
	}
	if !toolPattern.MatchString(p.Tool) {
		return fmt.Errorf("tool %q must be a lowercase executable name", p.Tool)
	}
	if !versionPattern.MatchString(p.Version) {
		return fmt.Errorf("version %q must be a pinned version such as 1.12.5", p.Version)
	}
	for name, value := range p.Environment {
		if !environmentPattern.MatchString(name) {
			return fmt.Errorf("environment key %q must be an upper snake case name", name)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("environment %q must not contain NUL or line-control characters", name)
		}
	}
	if len(p.Artifacts) == 0 {
		return errors.New("artifacts must bind at least one platform")
	}
	for platform, artifact := range p.Artifacts {
		if !platformPattern.MatchString(platform) {
			return fmt.Errorf("artifact key %q must use the <goos>-<goarch> form", platform)
		}
		if err := artifact.validate(platform); err != nil {
			return err
		}
	}
	return nil
}

func (a Artifact) validate(platform string) error {
	if !strings.HasPrefix(a.URL, "https://") {
		return fmt.Errorf("artifact %q url must use https", platform)
	}
	if strings.ContainsAny(a.URL, "\x00\r\n") {
		return fmt.Errorf("artifact %q url must not contain control characters", platform)
	}
	if !digestPattern.MatchString(a.SHA256) {
		return fmt.Errorf("artifact %q sha256 must be 64 lowercase hex characters", platform)
	}
	if a.Signature != "" && strings.ContainsAny(a.Signature, "\x00\r\n") {
		return fmt.Errorf("artifact %q signature reference must not contain control characters", platform)
	}
	return nil
}

func (d Discovery) validate() error {
	if strings.TrimSpace(d.Roots.FileGlob) == "" || strings.ContainsAny(d.Roots.FileGlob, "\x00\r\n") {
		return errors.New("roots.fileGlob must be a non-empty glob")
	}
	seen := make(map[string]struct{}, len(d.ExcludeDirs))
	for index, directory := range d.ExcludeDirs {
		if strings.TrimSpace(directory) == "" || strings.ContainsAny(directory, "\x00\r\n") {
			return fmt.Errorf("excludeDirs[%d] must be a non-empty directory name", index)
		}
		if _, found := seen[directory]; found {
			return fmt.Errorf("excludeDirs[%d] %q is not unique", index, directory)
		}
		seen[directory] = struct{}{}
	}
	return nil
}

func (a Assertion) validate() error {
	if !identityPattern.MatchString(a.Name) {
		return fmt.Errorf("assertion name %q must be a lowercase kebab identifier", a.Name)
	}
	if err := validateCommand(a.Command); err != nil {
		return err
	}
	for index, argument := range a.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("args[%d] must not contain NUL or line-control characters", index)
		}
	}
	if a.Expect == "" {
		return errors.New("expect must not be empty")
	}
	return nil
}

func (g Gate) validate(capability string) error {
	if !identityPattern.MatchString(g.Name) {
		return fmt.Errorf("gate name %q must be a lowercase kebab identifier", g.Name)
	}
	if !strings.HasPrefix(g.Name, capability+"-") {
		return fmt.Errorf("gate name %q must be prefixed by the capability %q", g.Name, capability)
	}
	if err := validateCommand(g.Command); err != nil {
		return err
	}
	for index, argument := range g.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("args[%d] must not contain NUL or line-control characters", index)
		}
	}
	if g.Scope != ScopeRepository && g.Scope != ScopePerRoot {
		return fmt.Errorf("scope %q must be %q or %q", g.Scope, ScopeRepository, ScopePerRoot)
	}
	if g.Timeout != "" {
		timeout, err := time.ParseDuration(g.Timeout)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("timeout %q must be a positive Go duration", g.Timeout)
		}
	}
	return nil
}

func validateCommand(command string) error {
	if strings.TrimSpace(command) == "" || strings.ContainsAny(command, "\x00\r\n") {
		return errors.New("command must be a non-empty executable name or path without control characters")
	}
	return nil
}
