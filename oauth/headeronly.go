package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Standalone struct {
	// Credentials specifies the client key and secret.
	// Also known as the consumer key and secret
	Credentials Credentials

	// Token specifies the token and token secret.
	Token Credentials

	// Realm is ignored if it is an empty string, otherwise it is added to the Authorization header
	Realm string
}

func (c *Standalone) authorizationHeader(httpMethod string, parsedURL *url.URL) (string, error) {
	p, err := c.oauthParams(httpMethod, parsedURL)
	if err != nil {
		return "", err
	}
	var h []byte
	// Append parameters in a fixed order to support testing.
	for _, k := range oauthKeys {
		if v, ok := p[k]; ok {
			if h == nil {
				h = []byte(`OAuth `)
				if c.Realm != "" {
					h = append(h, []byte(`realm="`)...)
					h = append(h, []byte(c.Realm)...)
					h = append(h, []byte(`",`)...)
				}
			} else {
				h = append(h, ", "...)
			}
			h = append(h, k...)
			h = append(h, `="`...)
			h = append(h, encode(v, false)...)
			h = append(h, '"')
		}
	}
	return string(h), nil
}

func (c *Standalone) oauthParams(httpMethod string, parsedURL *url.URL) (map[string]string, error) {
	oauthParams := map[string]string{
		"oauth_consumer_key":     c.Credentials.Token,
		"oauth_signature_method": "HMAC-SHA256",
		"oauth_version":          "1.0",
	}

	oauthParams["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	oauthParams["oauth_nonce"] = nonce()

	oauthParams["oauth_token"] = c.Token.Token

	testHook(oauthParams)

	oauthParams["oauth_signature"] = c.hmacSignature(c.Token.Secret, httpMethod, parsedURL, sha256.New, oauthParams)
	return oauthParams, nil
}

func (c *Standalone) hmacSignature(tokenSecret string, method string, parsedURL *url.URL, h func() hash.Hash, oauthParams map[string]string) string {
	key := encode(c.Credentials.Secret, false)
	key = append(key, '&')
	key = append(key, encode(tokenSecret, false)...)
	hm := hmac.New(h, key)
	writeBaseString(hm, method, parsedURL, nil, oauthParams)
	return base64.StdEncoding.EncodeToString(hm.Sum(key[:0]))
}

func (c *Standalone) Get(ctx context.Context, urlStr string, client *http.Client, header http.Header) (*http.Response, error) {
	return c.do(ctx, urlStr, http.MethodGet, nil, client, header)
}

func (c *Standalone) Post(ctx context.Context, urlStr string, client *http.Client, header http.Header, body io.Reader) (*http.Response, error) {
	return c.do(ctx, urlStr, http.MethodPost, body, client, header)
}

func (c *Standalone) do(ctx context.Context, urlStr, method string, body io.Reader, client *http.Client, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		req.Header[k] = v
	}

	auth, err := c.authorizationHeader(method, req.URL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth)
	req = req.WithContext(ctx)
	return client.Do(req)
}
