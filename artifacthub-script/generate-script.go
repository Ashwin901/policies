package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type ArtifactHubMetadata struct {
	Version          string `yaml:"version,omitempty"`
	Name             string `yaml:"name,omitempty"`
	DisplayName      string `yaml:"displayName,omitempty"`
	CreatedAt        string `yaml:"createdAt,omitempty"`
	Description      string `yaml:"description,omitempty"`
	LogoPath         string `yaml:"logoPath,omitempty"`
	LogoURL          string `yaml:"logoURL,omitempty"`
	Digest           string `yaml:"digest,omitempty"`
	License          string `yaml:"license,omitempty"`
	HomeURL          string `yaml:"homeURL,omitempty"`
	AppVersion       string `yaml:"appVersion,omitempty"`
	ContainersImages []struct {
		Name        string `yaml:"name,omitempty"`
		Image       string `yaml:"image,omitempty"`
		Whitelisted string `yaml:"whitelisted,omitempty"`
	} `yaml:"containersImages,omitempty"`
	ContainsSecurityUpdates string   `yaml:"containsSecurityUpdates,omitempty"`
	Operator                string   `yaml:"operator,omitempty"`
	Deprecated              string   `yaml:"deprecated,omitempty"`
	Prerelease              string   `yaml:"prerelease,omitempty"`
	Keywords                []string `yaml:"keywords,omitempty"`
	Links                   []struct {
		Name string `yaml:"name,omitempty"`
		URL  string `yaml:"url,omitempty"`
	} `yaml:"links,omitempty"`
	Readme  string `yaml:"readme,omitempty"`
	Install string `yaml:"install,omitempty"`
	Changes []struct {
		Kind        string `yaml:"kind,omitempty"`
		Description string `yaml:"description,omitempty"`
		Links       []struct {
			Name string `yaml:"name,omitempty"`
			URL  string `yaml:"url,omitempty"`
		} `yaml:"links,omitempty"`
	} `yaml:"changes,omitempty"`
	Maintainers []struct {
		Name  string `yaml:"name,omitempty"`
		Email string `yaml:"email,omitempty"`
	} `yaml:"maintainers,omitempty"`
	Provider struct {
		Name string `yaml:"name,omitempty"`
	} `yaml:"provider,omitempty"`
	Ignore          []string `yaml:"ignore,omitempty"`
	Recommendations []struct {
		URL string `yaml:"url,omitempty"`
	} `yaml:"recommendations,omitempty"`
	Screenshots []struct {
		Title string `yaml:"title,omitempty"`
		URL   string `yaml:"url,omitempty"`
	} `yaml:"screenshots,omitempty"`
	Annotations struct {
		Key1 string `yaml:"key1,omitempty"`
		Key2 string `yaml:"key2,omitempty"`
	} `yaml:"annotations,omitempty"`
}

const (
	sourceURL = "https://raw.githubusercontent.com/Ashwin901/policy-hub-automation/master/"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println("error while getting pwd")
		panic(err)
	}

	fmt.Println(pwd)
	rootDir := pwd
	policiesPath := filepath.Join(rootDir, "policies")
	dirEntry, err := os.ReadDir(policiesPath)
	if err != nil {
		fmt.Println("error while listing directories under policies")
		panic(err)
	}

	for _, entry := range dirEntry {
		if entry.Type().IsDir() {
			fmt.Println(entry.Name())
			constraintTemplateContent, err := os.ReadFile(filepath.Join(policiesPath, entry.Name(), entry.Name()+".yaml"))

			if err != nil {
				fmt.Println("error while reading", entry.Name()+".yaml")
				panic(err)
			}

			constraintTemplate := make(map[string]interface{})
			err = yaml.Unmarshal(constraintTemplateContent, &constraintTemplate)
			if err != nil {
				fmt.Println("error while unmarshaling", entry.Name()+".yaml")
				panic(err)
			}

			destination := filepath.Join(policiesPath, entry.Name())
			addArtifactHubMetadata(entry.Name(), destination, entry.Name(), constraintTemplate)
		}
	}
}

func addArtifactHubMetadata(sourceDirectory, destinationPath, ahBasePath string, constraintTemplate map[string]interface{}) {
	format := "2006-01-02 15:04:05Z"
	currentDateTime, err := time.Parse(format, time.Now().UTC().Format(format))
	if err != nil {
		fmt.Println("error while parsing current date time")
		panic(err)
	}

	artifactHubMetadata := &ArtifactHubMetadata{
		Version:     fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/version"]),
		Name:        fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["name"]),
		DisplayName: fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/title"]),
		CreatedAt:   currentDateTime.Format(time.RFC3339),
		Description: fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/description"]),
		HomeURL:     "https://github.com/Ashwin901/policy-hub-automation/tree/master/" + sourceDirectory,
		Keywords: []string{
			"kyverno",
			"policy",
		},
		Links: []struct {
			Name string "yaml:\"name,omitempty\""
			URL  string "yaml:\"url,omitempty\""
		}{
			{
				Name: "Source",
				URL:  "https://github.com/Ashwin901/policy-hub-automation/blob/master/" + ahBasePath + "/" + ahBasePath + ".yaml",
			},
		},
		Provider: struct {
			Name string `yaml:"name,omitempty"`
		}{
			Name: "Ashwin901",
		},
		Install: fmt.Sprintf("### Usage\n```shell\nkubectl apply -f %s\n```", sourceURL+filepath.Join(ahBasePath, ahBasePath+".yaml")),
		Readme: fmt.Sprintf(`# %s
%s`, constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/title"], constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/description"]),
	}

	artifactHubMetadataBytes, err := yaml.Marshal(artifactHubMetadata)
	if err != nil {
		fmt.Println("error while marshaling artifact hub metadata")
		panic(err)
	}

	err = os.WriteFile(filepath.Join(destinationPath, "artifacthub-pkg.yml"), artifactHubMetadataBytes, 0644)
	if err != nil {
		fmt.Println("error while writing artifact hub metadata")
		panic(err)
	}
}
