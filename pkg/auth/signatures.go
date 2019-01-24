package auth

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type SignatureMethod int

const (
	Md5Hash SignatureMethod = iota
	Md5Hmac
	Sha1Hmac
	Sha256Hmac
	Sha512Hmac
)

// The approach for generating an MD5 Hash is different to an HMAC - the key is just appended to the plaintext.
// This hash.Hash implementation just provides that ability in a way that's compatible with the HMAC hash approaches.
type md5Hash struct {
	hasher hash.Hash
	key    []byte
}

func (h *md5Hash) Write(p []byte) (n int, err error) {
	return h.hasher.Write(p)
}

func (h *md5Hash) Sum(b []byte) []byte {
	h.hasher.Write(h.key)
	return h.hasher.Sum(b)
}

func (h *md5Hash) Reset() {
	h.hasher.Reset()
}

func (h *md5Hash) Size() int {
	return h.hasher.Size()
}

func (h *md5Hash) BlockSize() int {
	return h.hasher.BlockSize()
}

func (m SignatureMethod) NewHash(key []byte) hash.Hash {
	switch m {
	case Md5Hash:
		return &md5Hash{
			md5.New(),
			key,
		}
	case Md5Hmac:
		return hmac.New(md5.New, key)
	case Sha1Hmac:
		return hmac.New(sha1.New, key)
	case Sha256Hmac:
		return hmac.New(sha256.New, key)
	case Sha512Hmac:
		return hmac.New(sha512.New, key)
	}
	panic("An unknown SignatureMethod was provided to NewHash.")
}

func generateSignature(params url.Values, key []byte, method SignatureMethod) string {
	if params.Get("timestamp") == "" {
		params.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	}
	hasher := method.NewHash(key)
	hasher.Write([]byte(stringToSign(params)))
	return hex.EncodeToString(hasher.Sum(nil))
}

/// Sign adds a valid `sig` parameter to the provided `params`
///
/// This function will also add a current `timestamp` parameter to `params` if one is not already present.
func Sign(params url.Values, key []byte, method SignatureMethod) {
	params.Del("sig") // Things can get really confusing if you don't do this.
	params.Set("sig", generateSignature(params, key, method))
}

func ValidateSignature(params url.Values, key []byte, method SignatureMethod) bool {
	paramsWithoutSig := url.Values{}
	for k, v := range params {
		if k != "sig" {
			paramsWithoutSig[k] = v
		}
	}
	sig := generateSignature(paramsWithoutSig, key, method)
	providedSig := params.Get("sig")

	return sig == providedSig
}

var valueEscaper = strings.NewReplacer("&", "_", "=", "_")

func stringToSign(params url.Values) string {
	result := strings.Builder{}
	for _, key := range sortedKeys(params) {
		result.WriteRune('&')
		result.WriteString(key)
		result.WriteRune('=')
		result.WriteString(valueEscaper.Replace(params[key][0]))
	}
	return result.String()
}

func sortedKeys(params url.Values) []string {
	keys := make([]string, len(params))
	i := 0
	for k := range params {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	return keys
}
