// Copyright 2019 Google Inc. All Rights Reserved.
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

// sendgmail is a tool that uses Gmail in order to mimic `sendmail` for `git send-email`.
//
// USAGE:
//
// $ /PATH/TO/sendgmail -sender=USERNAME@gmail.com -setup
//
// $ git send-email --smtp-server=/PATH/TO/sendgmail --smtp-server-option=-sender=USERNAME@gmail.com ...
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	googleOAuth2 "golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

var (
	sender string
	setUp  bool
	dummyF string
	dummyI bool
)

func init() {
	flag.StringVar(&sender, "sender", "", "Specifies the sender's email address.")
	flag.BoolVar(&setUp, "setup", false, "If true, sendgmail sets up the sender's OAuth2 token and then exits.")
	flag.StringVar(&dummyF, "f", "", "Dummy flag for compatibility with sendmail.")
	flag.BoolVar(&dummyI, "i", true, "Dummy flag for compatibility with sendmail.")
}

func main() {
	flag.Parse()
	// Originally, this checked for "@gmail.com" as a suffix,
	// but any Google Workspace domain can also be supported.
	// Checking only for '@' gives rudimentary assurance that
	// the user specified an email address; the complexity of
	// performing deeper checks is unwarranted at this point.
	if !strings.ContainsRune(sender, '@') {
		log.Fatalf("-sender must specify an email address.")
	}
	config := getConfig()
	if setUp {
		setUpToken(config)
		return
	}
	sendMessage(config)
}

func configJSON() []byte {
	configJSON, err := os.ReadFile(configPath())
	if err != nil {
		log.Fatalf("Failed to read config: %v.", err)
	}
	return configJSON
}

func getConfig() *oauth2.Config {
	config, err := googleOAuth2.ConfigFromJSON(configJSON(), "https://www.googleapis.com/auth/gmail.send")
	if err != nil {
		log.Fatalf("Failed to parse config: %v.", err)
	}
	return config
}

func setUpToken(config *oauth2.Config) {
	state := uuid.NewString()

	// Parse RedirectURL to determine if it's a local redirect
	u, err := url.Parse(config.RedirectURL)
	if err != nil {
		log.Fatalf("Failed to parse redirect_uris[0]: %v", err)
	}

	// Extract the host and port
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// If no port is specified, assume default port 80
		host = u.Host
		port = "80"
	}

	// Check if host is localhost or loopback IP
	local := false
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		local = true
	} else if host == "localhost" {
		local = true
	}

	server := &http.Server{Addr: net.JoinHostPort(host, port)}

	codeChan := make(chan string)

	callbackPath := u.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "" {
			codeChan <- code
			fmt.Fprintf(w, "Authorisation code received. You can close this window.")
			go func() {
				time.Sleep(1 * time.Second)
				server.Shutdown(context.Background())
			}()
		} else {
			http.Error(w, "No code received", http.StatusBadRequest)
		}
	})

	authHandler := func(authCodeURL string) (string, string, error) {
		fmt.Println()
		fmt.Println("1. Ensure that you are logged in as", sender, "in your browser.")
		fmt.Println()

		if local {
			go func() {
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Fatalf("Failed to start server: %v.", err)
				}
			}()
		}

		fmt.Println("2. Open the following link and authorise sendgmail:")
		fmt.Println(authCodeURL + "&access_type=offline&prompt=consent") // hack to obtain a refresh token

		var code string
		if local {
			code = <-codeChan
		} else {
			fmt.Println()
			fmt.Println("3. Enter the authorisation code:")
			if _, err := fmt.Scan(&code); err != nil {
				log.Fatalf("Failed to read authorisation code: %v.", err)
			}
		}

		fmt.Println()

		return code, state, nil
	}
	verifier := uuid.NewString()
	s256 := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(s256[:])
	pkceParams := authhandler.PKCEParams{Challenge: challenge, ChallengeMethod: "S256", Verifier: verifier}
	credentialsParams := googleOAuth2.CredentialsParams{Scopes: config.Scopes, State: state, AuthHandler: authHandler, PKCE: &pkceParams}
	credentials, err := googleOAuth2.CredentialsFromJSONWithParams(context.Background(), configJSON(), credentialsParams)
	if err != nil {
		log.Fatalf("Failed to obtain credentials: %v.", err)
	}
	token, err := credentials.TokenSource.Token()
	if err != nil {
		log.Fatalf("Failed to exchange authorisation code for token: %v.", err)
	}
	tokenFile, err := os.OpenFile(tokenPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open token file for writing: %v.", err)
	}
	defer tokenFile.Close()
	if err := json.NewEncoder(tokenFile).Encode(token); err != nil {
		log.Fatalf("Failed to write token: %v.", err)
	}
}

// checkLines checks if the body of a message contains lines that are likely to be
// mangled by Gmail. It returns true if mangling is likely, false otherwise.
// Mangling is considered likely if a line is longer than lineLengthLimit, and a
// word on that line starts at or after columnIndexTrigger and crosses the
// lineLengthLimit. This is a heuristic based on observed Gmail behavior.
func checkLines(body string) bool {
	const lineLengthLimit = 78
	const columnIndexTrigger = 16

	bodyLines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")

	for _, line := range bodyLines {
		runes := []rune(line)
		if len(runes) <= lineLengthLimit {
			continue
		}

		inWord := false
		wordStart := -1
		for i, r := range runes {
			if !unicode.IsSpace(r) {
				if !inWord {
					inWord = true
					wordStart = i
				}
			} else { // is space
				if inWord {
					inWord = false
					// Word ended at i-1. wordEnd is exclusive index i.
					wordEnd := i
					if wordEnd > lineLengthLimit && wordStart >= columnIndexTrigger {
						return true
					}
				}
			}
		}
		// Handle word at end of line
		if inWord {
			wordEnd := len(runes)
			if wordEnd > lineLengthLimit && wordStart >= columnIndexTrigger {
				return true
			}
		}
	}
	return false
}

// decodeBody decodes the message body based on the provided transferEncoding.
// It supports "quoted-printable" and "base64" encodings. If decoding fails
// or the encoding is unsupported, it logs a fatal error.
func decodeBody(body, transferEncoding string) string {
	if strings.EqualFold(transferEncoding, "quoted-printable") {
		qpr, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
		if err != nil {
			log.Fatalf("Failed to decode quoted-printable body: %v.", err)
		}
		return string(qpr)
	} else if strings.EqualFold(transferEncoding, "base64") {
		decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(body))
		decodedBytes, err := io.ReadAll(decoder)
		if err != nil {
			log.Fatalf("Failed to decode base64 body: %v.", err)
		}
		return string(decodedBytes)
	} else if transferEncoding == "" ||
		strings.EqualFold(transferEncoding, "7bit") ||
		strings.EqualFold(transferEncoding, "8bit") {
		return body
	}
	log.Fatalf("Unsupported Content-Transfer-Encoding: %q", transferEncoding)
	return "" // Unreachable
}

// checkMessageBody analyzes an email message to determine if it is likely to be
// mangled by Gmail. It specifically checks for long lines in text/plain
// messages that can be reformatted by Gmail, breaking patches. If such a
// message is detected, it logs a fatal error.
func checkMessageBody(message []byte) {
	msgStr := string(message)
	separator := "\n\n"
	headerEnd := strings.Index(msgStr, separator)
	if headerEnd == -1 {
		separator = "\r\n\r\n"
		headerEnd = strings.Index(msgStr, separator)
	}

	var headerPart string
	lineEnding := "\n"

	if headerEnd != -1 {
		headerPart = msgStr[:headerEnd]
		if strings.Contains(headerPart, "\r\n") {
			lineEnding = "\r\n"
		}
	} else {
		// No separator means the entire message is headers with no body.
		// This can be the case for a cover letter from git send-email.
		headerPart = msgStr
		if strings.Contains(headerPart, "\r\n") {
			lineEnding = "\r\n"
		}
	}

	lines := strings.Split(headerPart, lineEnding)
	contentTypeFound := false
	transferEncoding := ""

	var contentTypeValue string

	for _, line := range lines {
		if len(line) > len("Content-Type:") && strings.EqualFold(line[:len("Content-Type:")], "Content-Type:") {
			if !contentTypeFound { // only find first
				contentTypeFound = true
				contentTypeValue = strings.TrimSpace(line[len("Content-Type:"):])
			}
		} else if len(line) > len("Content-Transfer-Encoding:") && strings.EqualFold(line[:len("Content-Transfer-Encoding:")], "Content-Transfer-Encoding:") {
			if transferEncoding == "" { // only find first
				transferEncoding = strings.TrimSpace(line[len("Content-Transfer-Encoding:"):])
			}
		}
	}

	isTextPlain := false
	if contentTypeFound {
		mediaType, _, err := mime.ParseMediaType(contentTypeValue)
		if err == nil && mediaType == "text/plain" {
			isTextPlain = true
		}
	} else {
		// No content type header implies text/plain.
		isTextPlain = true
	}

	if !isTextPlain {
		// If the message isn't text/plain, then we don't care since Gmail won't mangle non-plaintext messages.
		return
	}

	var bodyOnly string
	if headerEnd != -1 {
		bodyOnly = msgStr[headerEnd+len(separator):]
	}

	decodedBody := decodeBody(bodyOnly, transferEncoding)
	willBeMangled := checkLines(decodedBody)
	if willBeMangled {
		log.Fatalf("sendgmail has detected that this message is likely to be mangled by Gmail. To send this message, please use SMTP instead.")
	}
}

func sendMessage(config *oauth2.Config) {
	tokenFile, err := os.Open(tokenPath())
	if err != nil {
		log.Fatalf("Failed to open token file for reading: %v.", err)
	}
	defer tokenFile.Close()

	var token oauth2.Token
	if err := json.NewDecoder(tokenFile).Decode(&token); err != nil {
		log.Fatalf("Failed to read token: %v.", err)
	}

	ctx := context.Background()
	tokenSource := config.TokenSource(ctx, &token)

	message, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Failed to read message: %v.", err)
	}

	checkMessageBody(message)

	gmailService, err := gmail.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		log.Fatalf("Failed to create gmail service: %v.", err)
	}

	_, err = gmailService.Users.Messages.
		Send(
			"me",
			&gmail.Message{
				Raw: base64.URLEncoding.EncodeToString(message),
			},
		).
		Do()
	if err != nil {
		log.Fatalf("Failed to send message: %v.", err)
	}
}

func userConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	if dir := os.Getenv("HOME"); dir != "" {
		return filepath.Join(dir, ".config")
	}
	panic("Neither $XDG_CONFIG_HOME nor $HOME is defined.")
}

func userHomeDir() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get user home directory: %v.", err)
	}
	return dir
}

var isXDG = sync.OnceValue(func() bool {
	if _, err := os.Stat(filepath.Join(userConfigDir(), "sendgmail", "config.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(userHomeDir(), ".sendgmail.json")); err == nil {
		return false
	}
	return true
})

func configPath() string {
	if isXDG() {
		return filepath.Join(userConfigDir(), "sendgmail", "config.json")
	} else {
		return filepath.Join(userHomeDir(), ".sendgmail.json")
	}
}

func tokenPath() string {
	if isXDG() {
		return filepath.Join(userConfigDir(), "sendgmail", "token."+sender+".json")
	} else {
		return filepath.Join(userHomeDir(), ".sendgmail."+sender+".json")
	}
}
