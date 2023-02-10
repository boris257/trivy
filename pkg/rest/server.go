package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/go-chi/chi/v5"
	"golang.org/x/xerrors"
)

type ComponentReportRequest struct {
	Coordinates []string `json:"coordinates"`
}

type ComponentReport struct {
	Coordinates     string          `json:"coordinates"`
	Description     string          `json:"description"`
	Reference       string          `json:"reference"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Id            string   `json:"id"`
	DisplayName   string   `json:"displayName"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	CVSSScore     float32  `json:"cvssScore"`
	CVSSVector    string   `json:"cvssVector"`
	CWE           string   `json:"cwe"`
	CVE           string   `json:"cve"`
	Reference     string   `json:"reference"`
	VersionRanges []string `json:"versionRanges"`
}

type scannerServer struct {
	vulnClient vulnerability.Client
}

func newScannerServer() *scannerServer {
	return &scannerServer{
		vulnClient: vulnerability.NewClient(db.Config{}),
	}
}

func (s *scannerServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	status, err := s.ComponentReportRequestHandler(resp, req)
	if err != nil {
		log.Logger.Error(err.Error())
	}
	resp.WriteHeader(status)
}

func (s *scannerServer) ComponentReportRequestHandler(resp http.ResponseWriter, req *http.Request) (int, error) {
	orgId, err := url.PathUnescape(chi.URLParam(req, "org_id"))
	if err != nil {
		return http.StatusInternalServerError, xerrors.Errorf("unescape org_id error: %w", err)
	}
	packageURL, err := url.PathUnescape(chi.URLParam(req, "purl"))
	if err != nil {
		return http.StatusInternalServerError, xerrors.Errorf("unescape purl error: %w", err)
	}

	// Parse PURL to get a trivy Package
	log.Logger.Infof("Scan package %s org %s", packageURL, orgId)
	p, err := purl.FromString(packageURL)
	if err != nil {
		return http.StatusInternalServerError, xerrors.Errorf("parse purl error: %w", err)
	}
	pkg := p.Package()

	// Fill pkg fields with cdx props
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return http.StatusInternalServerError, xerrors.Errorf("read http body error: %w", err)
	}

	var props []cdx.Property
	if len(bytes.TrimSpace(data)) > 0 {
		err = json.Unmarshal(data, &props)
		if err != nil {
			return http.StatusInternalServerError, xerrors.Errorf("json parse http body error: %w", err)
		}
		for _, prop := range props {
			if strings.HasPrefix(prop.Name, cyclonedx.Namespace) {
				switch strings.TrimPrefix(prop.Name, cyclonedx.Namespace) {
				case cyclonedx.PropertyPkgID:
					pkg.ID = prop.Value
				case cyclonedx.PropertySrcName:
					pkg.SrcName = prop.Value
				case cyclonedx.PropertySrcVersion:
					pkg.SrcVersion = prop.Value
				case cyclonedx.PropertySrcRelease:
					pkg.SrcRelease = prop.Value
				case cyclonedx.PropertySrcEpoch:
					pkg.SrcEpoch, err = strconv.Atoi(prop.Value)
					if err != nil {
						return http.StatusInternalServerError, xerrors.Errorf("failed to parse source epoch: %w", err)
					}
				case cyclonedx.PropertyModularitylabel:
					pkg.Modularitylabel = prop.Value
				case cyclonedx.PropertyLayerDiffID:
					pkg.Layer.DiffID = prop.Value
				}
			}
		}
	}

	// Detect vulnerabilities
	var vulns []types.DetectedVulnerability
	if p.IsOSPkg() {
		// Vulnerability detectors use Src* fields so we have to fix it
		if pkg.SrcName == "" {
			pkg.SrcName = pkg.Name
		}
		if pkg.SrcVersion == "" {
			pkg.SrcVersion = pkg.Version
		}
		if pkg.SrcRelease == "" {
			pkg.SrcRelease = pkg.Release
		}
		if pkg.SrcEpoch == 0 {
			pkg.SrcEpoch = pkg.Epoch
		}
		// Find out os family and name from distro
		distro := p.Qualifiers.Map()["distro"]
		distParts := strings.SplitN(distro, "-", 2)
		var osFamily, osName string
		osFamily = p.Namespace
		if len(distParts) == 1 {
			osName = distParts[0]
		} else {
			osName = distParts[1]
		}
		// Detect os package vulnerabilities
		vulns, err = ScanOsPkg(osFamily, osName, pkg)
		if err != nil {
			return http.StatusInternalServerError, xerrors.Errorf("scan package %s error: %w", packageURL, err)
		}
	} else {
		// Detect library package vulnerabilities
		vulns, err = ScanLibraryPkg(p.PackageType(), pkg.ID, pkg.Name, pkg.Version)
		if err != nil {
			return http.StatusInternalServerError, xerrors.Errorf("scan package %s error: %w", packageURL, err)
		}
	}
	s.vulnClient.FillInfo(vulns)

	// Convert every DetectedVulnerability to IssueResource
	issues := make([]IssueResource, len(vulns))
	for i, vuln := range vulns {
		issues[i].Id = vuln.VulnerabilityID
		issues[i].Type = "issue"
		issues[i].Attributes.Key = vuln.VulnerabilityID
		issues[i].Attributes.Title = vuln.Title
		issues[i].Attributes.Type = "package_vulnerability"
		if vuln.PublishedDate != nil {
			issues[i].Attributes.CreatedAt = vuln.PublishedDate.Format(time.RFC3339)
		}
		if vuln.LastModifiedDate != nil {
			updatedAt := vuln.LastModifiedDate.Format(time.RFC3339)
			issues[i].Attributes.UpdatedAt = &updatedAt
		}
		issues[i].Attributes.Description = vuln.Description
		var problems []Problem
		for _, cweid := range vuln.CweIDs {
			problems = append(problems, Problem{
				Id:     cweid,
				Source: "CWE",
			})
		}
		if vuln.DataSource != nil {
			problems = append(problems, Problem{
				Id:     vuln.VulnerabilityID,
				Source: strings.ToUpper(string(vuln.DataSource.ID)),
			})
		}
		issues[i].Attributes.Problems = problems
		if vuln.FixedVersion != "" {
			issues[i].Attributes.Coordinates = []Coordinate{{
				Remedies: []Remedy{{
					Type:        "indeterminate",
					Description: fmt.Sprintf("Upgrade the package version to %s to fix this vulnerability", vuln.FixedVersion),
					Details:     Details{UpgradePackage: vuln.FixedVersion},
				}},
				Representation: []string{vuln.FixedVersion},
			}}
		}
		var severities []Severity
		for src, sev := range vuln.VendorSeverity {
			cvss := vuln.CVSS[src]
			severities = append(severities, Severity{
				Source: strings.ToUpper(string(src)),
				Level:  strings.ToLower(sev.String()),
				Score:  cvss.V3Score,
				Vector: cvss.V3Vector,
			})
		}
		issues[i].Attributes.Severities = severities
		if len(severities) > 0 {
			issues[i].Attributes.EffectiveSeverityLevel = EffectiveSeverityLevel(severities[0].Level)
		}
		var references []Reference
		for _, ref := range vuln.References {
			references = append(references, Reference{Url: ref})
		}
		issues[i].Attributes.Slots.References = references
		issues[i].Attributes.Slots.Exploit = "Not Defined"
		if vuln.PublishedDate != nil {
			issues[i].Attributes.Slots.PublicationTime = vuln.PublishedDate.Format(time.RFC3339)
		}
	}

	doc := IssuesDocument{
		Jsonapi: JsonApi{
			Version: "1.0",
		},
		Meta: &IssuesMeta{
			Package: PackageMeta{
				Name:      p.Name,
				Namespace: p.Namespace,
				Type:      p.Type,
				Url:       packageURL,
				Version:   p.Version,
			},
		},
		Data: issues,
	}

	data, err = json.Marshal(&doc)
	if err != nil {
		return http.StatusInternalServerError, xerrors.Errorf("marshal response %s error: %w", packageURL, err)
	}

	_, err = resp.Write(data)
	if err != nil {
		return http.StatusInternalServerError, xerrors.Errorf("write response %s error: %w", packageURL, err)
	}

	return http.StatusOK, nil
}
