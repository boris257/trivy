package rest

import (
	"time"
)

type JsonApi struct {
	// Version of the JSON API specification this server supports.
	Version string `json:"version"`
}

type LinkProperty interface{}

type Links struct {
	PaginatedLinks
	Related *LinkProperty `json:"related,omitempty"`
}

type PaginatedLinks struct {
	First *LinkProperty `json:"first,omitempty"`
	Last  *LinkProperty `json:"last,omitempty"`
	Next  *LinkProperty `json:"next,omitempty"`
	Prev  *LinkProperty `json:"prev,omitempty"`
	Self  *LinkProperty `json:"self,omitempty"`
}

// Free-form object that may contain non-standard information.
type Meta struct {
	AdditionalProperties map[string]interface{} `json:"-"`
}

type PackageMeta struct {
	// The package’s name
	Name string `json:"name,omitempty"`

	// A name prefix, such as a maven group id or docker image owner
	Namespace string `json:"namespace,omitempty"`

	// The package type or protocol
	Type string `json:"type,omitempty"`

	// The purl of the package
	Url string `json:"url,omitempty"`

	// The version of the package
	Version string `json:"version,omitempty"`
}

type Attributes struct {
	Coordinates []Coordinate `json:"coordinates,omitempty"`
	CreatedAt   string       `json:"created_at,omitempty"`

	// A description of the issue in Markdown format
	Description string `json:"description,omitempty"`

	// The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
	EffectiveSeverityLevel EffectiveSeverityLevel `json:"effective_severity_level,omitempty"`

	// The vulnerability ID.
	Key      string    `json:"key,omitempty"`
	Problems []Problem `json:"problems,omitempty"`

	// The severity level of the vulnerability: ‘low’, ‘medium’, ‘high’ or ‘critical’.
	Severities []Severity `json:"severities,omitempty"`
	Slots      Slots      `json:"slots,omitempty"`

	// A human-readable title for this issue.
	Title string `json:"title,omitempty"`

	// The issue type
	Type string `json:"type,omitempty"`

	// When the vulnerability information was last modified.
	UpdatedAt *string `json:"updated_at,omitempty"`
}

type IssueResource struct {
	Attributes Attributes `json:"attributes,omitempty"`

	// The ID of the vulnerability.
	Id string `json:"id,omitempty"`

	// The type of the REST resource. Always ‘issue’.
	Type string `json:"type,omitempty"`
}

type Coordinate struct {
	Remedies []Remedy `json:"remedies,omitempty"`

	// The affected versions of this vulnerability.
	Representation []string `json:"representation,omitempty"`
}

type IssuesMeta struct {
	Package PackageMeta `json:"package,omitempty"`
}

type Problem struct {
	// When this problem was disclosed to the public.
	DisclosedAt *time.Time `json:"disclosed_at,omitempty"`

	// When this problem was first discovered.
	DiscoveredAt *time.Time `json:"discovered_at,omitempty"`
	Id           string     `json:"id"`
	Source       string     `json:"source"`

	// When this problem was last updated.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`

	// An optional URL for this problem.
	Url *string `json:"url,omitempty"`
}

type Details struct {
	// A minimum version to upgrade to in order to remedy the issue.
	UpgradePackage string `json:"upgrade_package,omitempty"`
}

type Remedy struct {
	// A markdown-formatted optional description of this remedy.
	Description string  `json:"description,omitempty"`
	Details     Details `json:"details,omitempty"`

	// The type of the remedy. Always ‘indeterminate’.
	Type string `json:"type,omitempty"`
}

type Severity struct {
	Level string `json:"level,omitempty"`

	// The CVSSv3 value of the vulnerability.
	Score float64 `json:"score,omitempty"`

	// The source of this severity. The value must be the id of a referenced problem or class, in which case that problem or class is the source of this issue. If source is omitted, this severity is sourced internally in the application.
	Source string `json:"source,omitempty"`

	// The CVSSv3 value of the vulnerability.
	Vector string `json:"vector,omitempty"`
}

type Reference struct {
	// Descriptor for an external reference to the issue
	Title string `json:"title,omitempty"`

	// URL for an external reference to the issue
	Url string `json:"url,omitempty"`
}

type Slots struct {
	// The time at which this vulnerability was disclosed.
	DisclosureTime *time.Time `json:"disclosure_time,omitempty"`

	// The exploit maturity. Value of ‘No Data’, ‘Not Defined’, ‘Unproven’, ‘Proof of Concept’, ‘Functional’ or ‘High’.
	Exploit string `json:"exploit,omitempty"`

	// The time at which this vulnerability was published.
	PublicationTime string      `json:"publication_time,omitempty"`
	References      []Reference `json:"references,omitempty"`
}

const (
	Critical EffectiveSeverityLevel = "critical"
	High     EffectiveSeverityLevel = "high"
	Info     EffectiveSeverityLevel = "info"
	Low      EffectiveSeverityLevel = "low"
	Medium   EffectiveSeverityLevel = "medium"
)

// The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
type EffectiveSeverityLevel string

type IssuesDocument struct {
	Data    []IssueResource `json:"data,omitempty"`
	Jsonapi JsonApi         `json:"jsonapi,omitempty"`
	Links   *PaginatedLinks `json:"links,omitempty"`
	Meta    *IssuesMeta     `json:"meta,omitempty"`
}
