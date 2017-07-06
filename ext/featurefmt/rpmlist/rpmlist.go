// Copyright 2017 Unbekandt Grégoire
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package rpmlist implementsa featurefmt.Lister and detects rpm packages from a json list
package rpmlist

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/pkg/tarutil"
)

const requiredFile string = "rpmlist"

type jsonFeature struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

type lister struct{}

func init() {
	featurefmt.RegisterLister("rpmlist", &lister{})
}

func (l lister) RequiredFilenames() []string {
	return []string{requiredFile}
}

// Detect detects packages using rpmlist from the input data
func (l lister) ListFeatures(files tarutil.FilesMap) ([]database.FeatureVersion, error) {
	f, hasFile := files[requiredFile]
	if !hasFile {
		return []database.FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]database.FeatureVersion)

	dec := json.NewDecoder(strings.NewReader(string(f)))
	// read open bracket
	_, err := dec.Token()
	if err != nil {
		log.WithError(err).Error("Couldn't read the token")
		return []database.FeatureVersion{}, nil
	}

	// Decode json
	for dec.More() {
		var feature jsonFeature
		if err := dec.Decode(&feature); err != nil {
			log.WithError(err).Warning("Couldn't parse package")
			continue
		}

		// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
		if feature.Package == "gpg-pubkey" {
			continue
		}

		// Parse version
		version := strings.Replace(feature.Version, "(none):", "", -1)
		err := versionfmt.Valid(rpm.ParserName, version)
		if err != nil {
			log.WithError(err).WithField("version", feature.Version).Warning("could not parse package version. skipping")
			continue
		}

		// Add package
		pkg := database.FeatureVersion{
			Feature: database.Feature{
				Name: feature.Package,
			},
			Version: version,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
	}

	// read closing bracket
	_, err = dec.Token()
	if err != nil {
		log.WithError(err).Error("Couldn't read the token")
		return []database.FeatureVersion{}, nil
	}

	// Convert the map to a slice
	packages := make([]database.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}
