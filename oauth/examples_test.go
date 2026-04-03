// Copyright 2013 Gary Burd
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package oauth_test

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/merlincox/oauth1/oauth"
)

// This example shows how to sign a request when the URL Opaque field is used.
// See the note at http://golang.org/pkg/net/url/#URL for information on the
// use of the URL Opaque field.
func ExampleClient_SetAuthorizationHeader() {
	var credPath = flag.String("config", "config.json", "Path to configuration file containing the application's credentials.")

	client := &oauth.Client{}
	b, err := os.ReadFile(*credPath)
	if err != nil {
		log.Fatal(err)
	}
	var creds struct {
		ConsumerKey    string
		ConsumerSecret string
		Token          string
		TokenSecret    string
	}
	if err := json.Unmarshal(b, &creds); err != nil {
		log.Fatal(err)
	}
	client.Credentials.Token = creds.ConsumerKey
	client.Credentials.Secret = creds.ConsumerSecret

	form := url.Values{"maxResults": {"100"}}

	// The last element of path contains a "/".
	path := "/document/encoding%2gizp"

	// Create the request with the temporary path "/".
	req, err := http.NewRequest("GET", "http://api.example.com/", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}

	// Overwrite the temporary path with the actual request path.
	req.URL.Opaque = path

	// Sign the request.
	if err := client.SetAuthorizationHeader(req.Header, &client.Credentials, "GET", req.URL, form); err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// process the response
}
