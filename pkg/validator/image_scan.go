package validator

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivyCache "github.com/aquasecurity/trivy/pkg/cache"
	trivyClient "github.com/aquasecurity/trivy/pkg/commands/client"
	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	dockerScan "github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"golang.org/x/xerrors"
)

func initializeResultClient() vulnerability.Client {
	dbConfig := db.Config{}
	vulnerabilityClient := vulnerability.NewClient(dbConfig)
	return vulnerabilityClient
}

func scanner(s v1beta1.Step) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10000)
	defer cancel()

	artifactOptions := option.ArtifactOption{
		Target:  s.Image,
		Timeout: time.Second * 5000,
	}

	opts := trivyClient.Option{
		ArtifactOption: artifactOptions,
		CustomHeaders:  http.Header{},
	}

	sc, cleanup, err := initializeScanner(ctx, opts)
	if err != nil {
		return fmt.Errorf("scanner initialize error: %w", err)
	}
	defer cleanup()
	scanOptions := types.ScanOptions{
		VulnType:            []string{types.VulnTypeOS, types.VulnTypeLibrary},
		SecurityChecks:      []string{types.SecurityCheckVulnerability},
		ScanRemovedPackages: false,
	}
	fmt.Printf("Vulnerability type:  %s", scanOptions.VulnType)
	results, err := sc.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return fmt.Errorf("error in image scan: %w", err)
	}
	resultClient := initializeResultClient()
	severities := splitSeverity(dbTypes.SeverityNames)
	for i := range results {
		vulns, err := resultClient.Filter(ctx, results[i].Vulnerabilities,
			severities, false, vulnerability.DefaultIgnoreFile, "")
		if err != nil {
			return xerrors.Errorf("filter error: %w", err)
		}
		results[i].Vulnerabilities = vulns
	}
	if len(results) > 0 {
		fmt.Printf("%d vulnerability/ies found", len(results[0].Vulnerabilities))

		if err = report.WriteResults("table", os.Stdout, severities, results, "", false); err != nil {
			return fmt.Errorf("could not write results: %v", fmt.Errorf("unable to write results: %w", err))
		}
	} else {
		fmt.Printf("no vulnerabilities found for image %s", s.Image)
	}
	return nil
}

func splitSeverity(severity []string) []dbTypes.Severity {
	var severities []dbTypes.Severity
	for _, s := range severity {
		severity, err := dbTypes.NewSeverity(s)
		if err != nil {
			fmt.Printf("unknown severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	return severities
}

func initializeScanner(ctx context.Context, opt trivyClient.Option) (dockerScan.Scanner, func(), error) {
	url := "http://localhost:4954"
	remoteCache := trivyCache.NewRemoteCache(trivyCache.RemoteURL(url), opt.CustomHeaders)

	// By default, apk commands are not analyzed.
	disabledAnalyzers := []analyzer.Type{analyzer.TypeApkCommand}
	if opt.ScanRemovedPkgs {
		disabledAnalyzers = []analyzer.Type{}
	}

	// TODO: fix the scanner option and enable config analyzers once we finalize the specification of config scanning.
	configScannerOptions := config.ScannerOption{}
	disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeYaml, analyzer.TypeTOML, analyzer.TypeJSON,
		analyzer.TypeDockerfile, analyzer.TypeHCL)

	// Scan an image in Docker Engine or Docker Registry
	s, cleanup, err := initializeDockerScanner(ctx, opt.Target, remoteCache, client.CustomHeaders(opt.CustomHeaders),
		client.RemoteURL(url), opt.Timeout, disabledAnalyzers, configScannerOptions)
	if err != nil {
		return dockerScan.Scanner{}, nil, xerrors.Errorf("unable to initialize the docker scanner: %w", err)
	}

	return s, cleanup, nil
}

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, customHeaders client.CustomHeaders, url client.RemoteURL, timeout time.Duration, disabled []analyzer.Type, configScannerOption config.ScannerOption) (dockerScan.Scanner, func(), error) {
	scannerScanner := client.NewProtobufClient(url)
	clientScanner := client.NewScanner(customHeaders, scannerScanner)
	dockerOption, err := types.GetDockerOption(timeout)
	if err != nil {
		return dockerScan.Scanner{}, nil, err
	}
	imageImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	if err != nil {
		return dockerScan.Scanner{}, nil, err
	}
	artifact, err := image2.NewArtifact(imageImage, artifactCache, disabled, configScannerOption)
	if err != nil {
		cleanup()
		return dockerScan.Scanner{}, nil, err
	}
	scanner2 := dockerScan.NewScanner(clientScanner, artifact)
	return scanner2, func() {
		cleanup()
	}, nil
}
