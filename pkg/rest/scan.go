package rest

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func ScanLibraryPkg(pkgType, pkgID, pkgName, pkgVersion string) ([]types.DetectedVulnerability, error) {
	driver, err := library.NewDriver(pkgType)
	if err != nil {
		return nil, err
	}
	return driver.DetectVulnerabilities(pkgID, pkgName, pkgVersion)
}

func ScanOsPkg(osFamily, osName string, pkg *ftypes.Package) ([]types.DetectedVulnerability, error) {
	detector := ospkg.Detector{}
	vulnerabilities, _, err := detector.Detect("", osFamily, osName, nil, time.Time{}, []ftypes.Package{*pkg})
	return vulnerabilities, err
}
