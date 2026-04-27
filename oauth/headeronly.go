package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"net/http"
	"strconv"
	"time"
)

type Authorizer struct {
	// Consumer specifies the client key and secret.
	// Also known as the consumer key and secret
	Consumer Credentials

	// Token specifies the token and token secret.
	Token Credentials

	// Realm is ignored if it is an empty string, otherwise it is added to the Authorization header
	Realm string
}

func (c *Authorizer) authorizationHeader(req *http.Request) (string, error) {
	p, err := c.oauthParams(req)
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

func (c *Authorizer) oauthParams(req *http.Request) (map[string]string, error) {
	oauthParams := map[string]string{
		"oauth_consumer_key":     c.Consumer.Token,
		"oauth_signature_method": "HMAC-SHA256",
		"oauth_version":          "1.0",
		"oauth_timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"oauth_nonce":            nonce(),
		"oauth_token":            c.Token.Token,
	}

	oauthParams["oauth_signature"] = c.hmacSignature(c.Token.Secret, req, sha256.New, oauthParams)

	return oauthParams, nil
}

func (c *Authorizer) hmacSignature(tokenSecret string, req *http.Request, h func() hash.Hash, oauthParams map[string]string) string {
	key := encode(c.Consumer.Secret, false)
	key = append(key, '&')
	key = append(key, encode(tokenSecret, false)...)
	hm := hmac.New(h, key)
	writeBaseString(hm, req.Method, req.URL, nil, oauthParams)

	return base64.StdEncoding.EncodeToString(hm.Sum(key[:0]))
}

func (c *Authorizer) authorize(req *http.Request) error {
	authHeader, err := c.authorizationHeader(req)
	if err != nil {
		return err
	}
	if req.Header == nil {
		req.Header = make(http.Header, 1)
	}
	req.Header.Set("Authorization", authHeader)

	return nil
}

func (c *Authorizer) Get(ctx context.Context, urlStr string, client *http.Client, header http.Header) (*http.Response, error) {
	return c.do(ctx, urlStr, http.MethodGet, nil, client, header)
}

func (c *Authorizer) Post(ctx context.Context, urlStr string, client *http.Client, header http.Header, body io.Reader) (*http.Response, error) {
	return c.do(ctx, urlStr, http.MethodPost, body, client, header)
}

func (c *Authorizer) do(ctx context.Context, urlStr, method string, body io.Reader, client *http.Client, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		req.Header[k] = v
	}

	auth, err := c.authorizationHeader(req)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth)
	req = req.WithContext(ctx)
	return client.Do(req)
}
