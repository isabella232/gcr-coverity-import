package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/e-conomic/gcr-coverity-import/pkg/coverity"
	"github.com/e-conomic/gcr-coverity-import/pkg/gcr"
)

var (
	project  = flag.String("project", "dev-vml-cm", "Google Project ID")
	root     = flag.String("root", "eu.gcr.io", "GCR Root")
	service  = flag.String("service", "", `Service to report on, ie. "ssn-pdfservice"`)
	tag      = flag.String("tag", "master", "Docker tag to report on")
	loglevel = zap.LevelFlag("loglevel", zapcore.InfoLevel, "loglevel")
	output   = flag.String("output", "", "where to write output, ie. output")
	report   = flag.String("report", "", "where to write report, ie. report.json")
)

func do() error {
	if *service == "" {
		return fmt.Errorf("service must be set")
	}
	if *output == "" {
		return fmt.Errorf("output must be set")
	}
	if *report == "" {
		return fmt.Errorf("report must be set")
	}
	lconf := zap.NewProductionConfig()
	lconf.Level.SetLevel(*loglevel)
	logger, err := lconf.Build()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)

	imagehash, err := gcr.FindImage(*root, *project, *service, *tag)
	if err != nil {
		return err
	}
	zap.L().Info("found latest image", zap.String("image", imagehash))
	occs, err := gcr.ListVulns(*project, imagehash)
	if err != nil {
		return err
	}

	results, err := coverity.TransformGrafeas(occs, *output)
	if err != nil {
		return err
	}

	file, err := os.Create(*report)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	err = enc.Encode(results)
	if err != nil {
		return err
	}
	zap.L().Info("report written", zap.String("report", *report))

	return nil
}

func main() {
	flag.Parse()
	if err := do(); err != nil {
		panic(err)
	}
}
