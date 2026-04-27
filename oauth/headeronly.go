package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"net/http"
	"strconv"
	"time"
)

type HMACSHA256Credentials struct {
	// Consumer specifies the client key and secret.
	// Also known as the consumer key and secret
	Consumer Credentials

	// Token specifies the token and token secret.
	Token Credentials

	// Realm is ignored if it is an empty string, otherwise it is added to the Authorization header
	Realm string
}

func (c *HMACSHA256Credentials) authorizationHeader(req http.Request) (string, error) {
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

func (c *HMACSHA256Credentials) oauthParams(req http.Request) (map[string]string, error) {
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

func (c *HMACSHA256Credentials) hmacSignature(tokenSecret string, req http.Request, h func() hash.Hash, oauthParams map[string]string) string {
	key := encode(c.Consumer.Secret, false)
	key = append(key, '&')
	key = append(key, encode(tokenSecret, false)...)
	hm := hmac.New(h, key)
	writeBaseString(hm, req.Method, req.URL, nil, oauthParams)

	return base64.StdEncoding.EncodeToString(hm.Sum(key[:0]))
}

func (c *HMACSHA256Credentials) authorise(req http.Request) error {
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
