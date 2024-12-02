package testutil

import (
	"fmt"
	"math/rand/v2"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/Azure/ARO-HCP/tooling/templatize/pkg/config"
	"github.com/Azure/ARO-HCP/tooling/templatize/pkg/pipeline"
)

var defaultRgName = "hcp-templatize"

func shouldRunE2E() bool {
	return os.Getenv("RUN_TEMPLATIZE_E2E") == "true"
}

type E2E interface {
	SetConfig(updates config.Variables)
	UseRandomRG()
	AddStep(step pipeline.Step)
	SetOSArgs()
	Persist() error
}

type e2eImpl struct {
	config    config.Variables
	makefile  string
	pipeline  pipeline.Pipeline
	bicepFile string
	paramFile string
	schema    string
	tmpdir    string
	rgName    string
}

var _ E2E = &e2eImpl{}

func newE2E(tmpdir string) e2eImpl {
	imp := e2eImpl{
		tmpdir: tmpdir,
		schema: `{"type": "object"}`,
		config: config.Variables{
			"$schema": "schema.json",
			"defaults": config.Variables{
				"region":       "westus3",
				"subscription": "ARO Hosted Control Planes (EA Subscription 1)",
				"rg":           defaultRgName,
			},
			"clouds": config.Variables{
				"public": config.Variables{
					"defaults": config.Variables{},
					"environments": config.Variables{
						"dev": config.Variables{
							"defaults": config.Variables{},
						},
					},
				},
			},
		},
		pipeline: pipeline.Pipeline{
			ServiceGroup: "Microsoft.Azure.ARO.Test",
			RolloutName:  "Test Rollout",
			ResourceGroups: []*pipeline.ResourceGroup{
				{
					Name:         "{{ .rg }}",
					Subscription: "{{ .subscription }}",
				},
			},
		},
		rgName: defaultRgName,
	}

	imp.SetOSArgs()
	return imp
}

func (e *e2eImpl) UseRandomRG() {

	chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	rg := "templatize-e2e-"

	for i := 0; i < 10; i++ {
		rg += string(chars[rand.IntN(len(chars))])
	}
	e.rgName = rg
	e.SetConfig(config.Variables{"defaults": config.Variables{"rg": rg}})
}

func (e *e2eImpl) SetOSArgs() {
	os.Args = []string{"test",
		"--cloud", "public",
		"--pipeline-file", e.tmpdir + "/pipeline.yaml",
		"--config-file", e.tmpdir + "/config.yaml",
		"--deploy-env", "dev",
		"--region", "westus3",
	}
}

func (e *e2eImpl) SetAKSName(aksName string) {
	e.pipeline.ResourceGroups[0].AKSCluster = aksName
}

func (e *e2eImpl) AddStep(step pipeline.Step) {
	e.pipeline.ResourceGroups[0].Steps = append(e.pipeline.ResourceGroups[0].Steps, &step)
}

func (e *e2eImpl) SetConfig(updates config.Variables) {
	config.MergeVariables(e.config, updates)
}

func (e *e2eImpl) Persist() error {
	if e.bicepFile != "" && e.paramFile != "" {
		err := os.WriteFile(e.tmpdir+"/test.bicep", []byte(e.bicepFile), 0644)
		if err != nil {
			return err
		}

		err = os.WriteFile(e.tmpdir+"/test.bicepparm", []byte(e.paramFile), 0644)
		if err != nil {
			return err
		}
	}

	if e.makefile != "" {
		err := os.WriteFile(e.tmpdir+"/Makefile", []byte(e.makefile), 0644)
		if err != nil {
			return err
		}
	}

	configBytes, err := yaml.Marshal(e.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	err = os.WriteFile(e.tmpdir+"/config.yaml", configBytes, 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(e.tmpdir+"/schema.json", []byte(e.schema), 0644)
	if err != nil {
		return err
	}

	pipelineBytes, err := yaml.Marshal(e.pipeline)
	if err != nil {
		return fmt.Errorf("failed to marshal pipeline: %w", err)
	}
	return os.WriteFile(e.tmpdir+"/pipeline.yaml", []byte(pipelineBytes), 0644)
}