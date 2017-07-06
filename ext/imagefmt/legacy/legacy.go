// Copyright 2017 Gregoire Unbekandt
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

package legacy

import (
	"encoding/json"
	"github.com/coreos/clair/ext/imagefmt"
	"github.com/coreos/clair/pkg/tarutil"
	"io"
	"io/ioutil"
	"strings"
)

// format implements imagefmt.Extractor and detects layer data in "Legacy" format
type format struct{}

// We want the files to be decoded to string because of EOL
type jsonLegacy struct {
	Packages map[string]string `json:"sysinfo_clair"`
}

// Enregistrement
func init() {
	imagefmt.RegisterExtractor("Legacy", &format{})
}

// Detect detects the required data from input path
// Reads json
func (f format) ExtractFiles(layerReader io.ReadCloser, toExtract []string) (tarutil.FilesMap, error) {
	data = make(map[string][]byte)
	jsonData := jsonLegacy{}

	// Read file
	fileContent, err := ioutil.ReadAll(layerReader)
	if err != nil {
		return data, err
	}

	// Decode json
	err = json.Unmarshal(fileContent, &jsonData)
	if err != nil {
		return data, err
	}

	// Iterate on toExtract (string -> []byte)
	for _, fileToExtract := range toExtract {
		if content, ok := jsonData.Packages[fileToExtract]; ok {
			data[fileToExtract] = []byte(content)
		}
	}

	return data, nil
}
