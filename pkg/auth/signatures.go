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
	MD5_HASH SignatureMethod = iota
	MD5_HMAC
	SHA1_HMAC
	SHA256_HMAC
	SHA512_HMAC
)

type MD5Hash struct {
	hasher hash.Hash
	key    []byte
}

func (h *MD5Hash) Write(p []byte) (n int, err error) {
	return h.hasher.Write(p)
}

func (h *MD5Hash) Sum(b []byte) []byte {
	h.hasher.Write(h.key)
	return h.hasher.Sum(b)
}

func (h *MD5Hash) Reset() {
	h.hasher.Reset()
}

func (h *MD5Hash) Size() int {
	return h.hasher.Size()
}

func (h *MD5Hash) BlockSize() int {
	return h.hasher.BlockSize()
}

func (m SignatureMethod) NewHash(key []byte) hash.Hash {
	switch m {
	case MD5_HASH:
		return &MD5Hash{
			md5.New(),
			key,
		}
	case MD5_HMAC:
		return hmac.New(md5.New, key)
	case SHA1_HMAC:
		return hmac.New(sha1.New, key)
	case SHA256_HMAC:
		return hmac.New(sha256.New, key)
	case SHA512_HMAC:
		return hmac.New(sha512.New, key)
	}
	panic("An unknown SignatureMethod was provided to NewHash.")
}

func GenerateSignature(params url.Values, key []byte, method SignatureMethod) string {
	if params.Get("timestamp") == "" {
		params.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	}
	hasher := method.NewHash(key)
	hasher.Write([]byte(stringToSign(params)))
	return hex.EncodeToString(hasher.Sum(nil))
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
