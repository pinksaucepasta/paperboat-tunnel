package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
)

type checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type fileEntry struct {
	Name      string     `json:"fileName"`
	SPDXID    string     `json:"SPDXID"`
	Checksums []checksum `json:"checksums"`
	Copyright string     `json:"copyrightText"`
	FileTypes []string   `json:"fileTypes"`
}

type packageEntry struct {
	Name             string     `json:"name"`
	SPDXID           string     `json:"SPDXID"`
	Version          string     `json:"versionInfo,omitempty"`
	DownloadLocation string     `json:"downloadLocation"`
	FilesAnalyzed    bool       `json:"filesAnalyzed"`
	LicenseConcluded string     `json:"licenseConcluded"`
	LicenseDeclared  string     `json:"licenseDeclared"`
	Copyright        string     `json:"copyrightText"`
	Checksums        []checksum `json:"checksums,omitempty"`
}

type relationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type document struct {
	SPDXVersion   string         `json:"spdxVersion"`
	DataLicense   string         `json:"dataLicense"`
	SPDXID        string         `json:"SPDXID"`
	Name          string         `json:"name"`
	Namespace     string         `json:"documentNamespace"`
	CreationInfo  map[string]any `json:"creationInfo"`
	Packages      []packageEntry `json:"packages"`
	Files         []fileEntry    `json:"files"`
	Relationships []relationship `json:"relationships"`
}

type artifact struct {
	name, path, version, license, source string
}

func main() {
	var tunnel, frps, caddy, fakeControl, output, created string
	flag.StringVar(&tunnel, "tunnel", "", "paperboat-tunnel binary")
	flag.StringVar(&frps, "frps", "", "pinned frps binary")
	flag.StringVar(&caddy, "caddy", "", "pinned Caddy binary")
	flag.StringVar(&fakeControl, "fake-control", "", "Phase 3 fake control binary")
	flag.StringVar(&output, "output", "", "SPDX JSON output")
	flag.StringVar(&created, "created", "", "RFC3339 build timestamp")
	flag.Parse()
	artifacts := []artifact{
		{"paperboat-tunnel", tunnel, "phase3", "MIT", "https://github.com/pinksaucepasta/paperboat-tunnel"},
		{"frps", frps, "v0.70.0+paperboat.1", "Apache-2.0", "https://github.com/pinksaucepasta/frp"},
		{"caddy", caddy, "v2.11.4", "Apache-2.0", "https://github.com/caddyserver/caddy"},
		{"paperboat-fake-control", fakeControl, "phase3", "MIT", "https://github.com/pinksaucepasta/paperboat-tunnel"},
	}
	if output == "" || created == "" {
		fatal(errors.New("output and created are required"))
	}
	document, err := generate(artifacts, created)
	if err != nil {
		fatal(err)
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(output, encoded, 0644); err != nil {
		fatal(err)
	}
}

func generate(artifacts []artifact, created string) (document, error) {
	result := document{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "paperboat-tunnel-release", CreationInfo: map[string]any{"created": created, "creators": []string{"Tool: paperboat-sbom"}}}
	modules := make(map[string]packageEntry)
	var namespace strings.Builder
	for _, item := range artifacts {
		if item.path == "" {
			return document{}, fmt.Errorf("%s path is required", item.name)
		}
		digest, err := fileSHA256(item.path)
		if err != nil {
			return document{}, err
		}
		namespace.WriteString(item.name + ":" + digest + "\n")
		packageID := spdxID("Package", item.name+"@"+item.version)
		fileID := spdxID("File", item.name+":"+digest)
		result.Packages = append(result.Packages, packageEntry{Name: item.name, SPDXID: packageID, Version: item.version, DownloadLocation: item.source, FilesAnalyzed: true, LicenseConcluded: item.license, LicenseDeclared: item.license, Copyright: "NOASSERTION", Checksums: []checksum{{"SHA256", digest}}})
		result.Files = append(result.Files, fileEntry{Name: "./bin/" + item.name, SPDXID: fileID, Checksums: []checksum{{"SHA256", digest}}, Copyright: "NOASSERTION", FileTypes: []string{"BINARY"}})
		result.Relationships = append(result.Relationships, relationship{packageID, "CONTAINS", fileID}, relationship{"SPDXRef-DOCUMENT", "DESCRIBES", packageID})
		info, err := buildinfo.ReadFile(item.path)
		if err != nil {
			return document{}, fmt.Errorf("read Go build info for %s: %w", item.name, err)
		}
		all := append([]*debug.Module{&info.Main}, info.Deps...)
		for _, module := range all {
			if module == nil || module.Path == "" {
				continue
			}
			version, sum := module.Version, module.Sum
			if module.Replace != nil {
				version, sum = module.Replace.Version, module.Replace.Sum
			}
			key := module.Path + "@" + version
			moduleID := spdxID("Package", key)
			if _, exists := modules[key]; !exists {
				entry := packageEntry{Name: module.Path, SPDXID: moduleID, Version: version, DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", Copyright: "NOASSERTION"}
				if strings.HasPrefix(sum, "h1:") {
					if decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(sum, "h1:")); decodeErr == nil {
						entry.Checksums = []checksum{{"SHA256", hex.EncodeToString(decoded)}}
					}
				}
				modules[key] = entry
			}
			result.Relationships = append(result.Relationships, relationship{packageID, "DEPENDS_ON", moduleID})
		}
	}
	keys := make([]string, 0, len(modules))
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result.Packages = append(result.Packages, modules[key])
	}
	sort.Slice(result.Packages, func(i, j int) bool { return result.Packages[i].SPDXID < result.Packages[j].SPDXID })
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].SPDXID < result.Files[j].SPDXID })
	sort.Slice(result.Relationships, func(i, j int) bool {
		left := result.Relationships[i].Element + result.Relationships[i].Type + result.Relationships[i].Related
		right := result.Relationships[j].Element + result.Relationships[j].Type + result.Relationships[j].Related
		return left < right
	})
	namespaceDigest := sha256.Sum256([]byte(namespace.String()))
	result.Namespace = "https://paperboat.dev/spdx/" + hex.EncodeToString(namespaceDigest[:])
	return result, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func spdxID(kind, value string) string {
	digest := sha256.Sum256([]byte(value))
	return "SPDXRef-" + kind + "-" + hex.EncodeToString(digest[:8])
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
