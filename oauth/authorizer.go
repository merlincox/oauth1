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

// Authorizer is a simplified Client which can authorize standard HTTP requests
type Authorizer struct {
	// Consumer specifies the client key and secret.
	// Also known as the consumer key and secret
	Consumer Credentials

	// Token specifies the token and token secret.
	Token Credentials

	// Realm is ignored if it is an empty string, otherwise it is added to the Authorization header
	Realm string
}

func (a *Authorizer) authorizationHeader(req *http.Request) string {
	params := a.oauthParams(req)
	var h []byte
	// Append parameters in a fixed order to support testing.
	for _, k := range oauthKeys {
		if v, ok := params[k]; ok {
			if h == nil {
				h = []byte(`OAuth `)
				if a.Realm != "" {
					h = append(h, []byte(`realm="`)...)
					h = append(h, []byte(a.Realm)...)
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
	return string(h)
}

func (a *Authorizer) oauthParams(req *http.Request) map[string]string {
	params := map[string]string{
		"oauth_consumer_key":     a.Consumer.Token,
		"oauth_signature_method": "HMAC-SHA256",
		"oauth_version":          "1.0",
		"oauth_timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"oauth_nonce":            nonce(),
		"oauth_token":            a.Token.Token,
	}

	params["oauth_signature"] = a.hmacSignature(a.Token.Secret, req, sha256.New, params)

	return params
}

func (a *Authorizer) hmacSignature(tokenSecret string, req *http.Request, h func() hash.Hash, oauthParams map[string]string) string {
	key := encode(a.Consumer.Secret, false)
	key = append(key, '&')
	key = append(key, encode(tokenSecret, false)...)
	hm := hmac.New(h, key)
	writeBaseString(hm, req.Method, req.URL, nil, oauthParams)

	return base64.StdEncoding.EncodeToString(hm.Sum(key[:0]))
}

// Authorize sets an Authorization header in the request, based on tokens and secrets and the request itself.
func (a *Authorizer) Authorize(req *http.Request) {
	authHeader := a.authorizationHeader(req)
	if req.Header == nil {
		req.Header = make(http.Header, 1)
	}
	req.Header.Set("Authorization", authHeader)
}
