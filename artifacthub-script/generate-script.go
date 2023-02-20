package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	sourceURL = "https://raw.githubusercontent.com/kyverno/policies/master/"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println("error while getting pwd")
		panic(err)
	}

	fmt.Println(pwd)
	rootDir := filepath.Join(pwd, "..")
	// policiesPath := filepath.Join(rootDir, "policies")
	policiesPath := rootDir
	fmt.Println(policiesPath)
	dirEntry, err := os.ReadDir(policiesPath)
	if err != nil {
		fmt.Println("error while listing directories under policies")
		panic(err)
	}

	for _, entry := range dirEntry {
		if entry.Type().IsDir() {
			if entry.Name() == ".git" || entry.Name() == ".github" {
				continue
			}
			policies, err := os.ReadDir(filepath.Join(policiesPath, entry.Name()))

			if err != nil {
				fmt.Println("error while listing directories under ", entry.Name())
				panic(err)
			}

			for _, policy := range policies {
				if policy.Type().IsDir() {
					fmt.Println(policy.Name())
					policyName := strings.ReplaceAll(policy.Name(), ".yaml", "")
					constraintTemplateContent, err := os.ReadFile(filepath.Join(policiesPath, entry.Name(), policy.Name(), policyName+".yaml"))

					if err != nil {
						fmt.Println("error while reading", policy.Name()+".yaml")
						if strings.Contains(policy.Name(), "_") {
							policyName = strings.ReplaceAll(policyName, "_", "-")
						} else {
							policyName = strings.ReplaceAll(policyName, "-", "_")
						}

						constraintTemplateContent, err = os.ReadFile(filepath.Join(policiesPath, entry.Name(), policy.Name(), policyName+".yaml"))

						if err != nil {
							fmt.Println("Could not read file ", policy.Name())
							// panic(err)
							continue
						}
					}

					constraintTemplate := make(map[string]interface{})
					err = yaml.Unmarshal(constraintTemplateContent, &constraintTemplate)
					if err != nil {
						fmt.Println("error while unmarshaling", policy.Name()+".yaml")
						panic(err)
					}

					destination := filepath.Join(policiesPath, entry.Name(), policy.Name())
					source := entry.Name() + "/" + policy.Name()
					addArtifactHubMetadata(source, destination, entry.Name(), policy.Name(), policyName, constraintTemplate)
				}
			}
		}
	}
}

func addArtifactHubMetadata(sourceDirectory, destinationPath, ahBasePath, ahPolicyPath, ahPolicyName string, constraintTemplate map[string]interface{}) {
	format := "2006-01-02 15:04:05Z"
	currentDateTime, err := time.Parse(format, time.Now().UTC().Format(format))
	if err != nil {
		fmt.Println("error while parsing current date time")
		panic(err)
	}

	templateHash := getConstraintTemplateHash(constraintTemplate)
	artifactHubMetadata := getMetadataIfExist(filepath.Join(destinationPath, "artifacthub-pkg.yml"))

	if artifactHubMetadata == nil {
		artifactHubMetadata = &ArtifactHubMetadata{
			Version:     "1.0.0",
			Name:        fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["name"]),
			DisplayName: fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/title"]),
			CreatedAt:   currentDateTime.Format(time.RFC3339),
			Description: fmt.Sprintf("%s", constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/description"]),
			HomeURL:     "https://github.com/kyverno/policies/tree/master/" + sourceDirectory,
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
					URL:  "https://github.com/kyverno/policies/blob/master/" + ahBasePath + "/" + ahPolicyPath + "/" + ahPolicyName + ".yaml",
				},
			},
			Provider: struct {
				Name string `yaml:"name,omitempty"`
			}{
				Name: "kyverno",
			},
			Install: fmt.Sprintf("### Usage\n```shell\nkubectl apply -f %s\n```", sourceURL+filepath.Join(ahBasePath, ahPolicyPath, ahPolicyPath+".yaml")),
			Readme: fmt.Sprintf(`# %s
	%s`, constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/title"], constraintTemplate["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["policies.kyverno.io/description"]),
		}
	} else {
		if templateHash != artifactHubMetadata.Digest {
			version := strings.Split(artifactHubMetadata.Version, ".")[0]
			newPolicyVersion, _ := strconv.Atoi(version)
			newPolicyVersion++
			artifactHubMetadata.Version = strconv.Itoa(newPolicyVersion) + ".0.0"
		}
	}

	artifactHubMetadata.Digest = templateHash

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

func getMetadataIfExist(metadataFilePath string) *ArtifactHubMetadata {
	if _, err := os.Stat(metadataFilePath); err == nil {
		metadataFile, err := os.ReadFile(metadataFilePath)
		if err != nil {
			fmt.Println("error while reading artifact hub metadata")
			panic(err)
		}

		artifactHubMetadata := ArtifactHubMetadata{}
		err = yaml.Unmarshal(metadataFile, &artifactHubMetadata)
		if err != nil {
			fmt.Println("error while unmarshaling artifact hub metadata")
			panic(err)
		}

		return &artifactHubMetadata
	}

	return nil
}

func getConstraintTemplateHash(constraintTemplate map[string]interface{}) string {
	constraintTemplateBytes, err := yaml.Marshal(constraintTemplate)
	if err != nil {
		fmt.Println("error while marshaling constraint template")
		panic(err)
	}

	hash := sha256.New()
	hash.Write(constraintTemplateBytes)
	return hex.EncodeToString(hash.Sum(nil))
}
