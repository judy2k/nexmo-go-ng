package auth

import (
	"bytes"
	"crypto/md5"
	"net/url"
	"testing"
)

func TestMD5HashReset(t *testing.T) {
	hasher1 := MD5Hash{
		md5.New(),
		[]byte("abcde"),
	}
	hasher2 := MD5Hash{
		md5.New(),
		[]byte("abcde"),
	}

	hasher1.Write([]byte("here is some stuff"))

	hasher2.Write([]byte("some irrelevant stuff"))
	hasher2.Reset()
	hasher2.Write([]byte("here is some stuff"))

	if !bytes.Equal(hasher1.Sum(nil), hasher2.Sum(nil)) {
		t.Errorf("Reset doesn't seem to reset MD5Hash state!")
	}
}

func TestMD5HashSize(t *testing.T) {
	h := MD5Hash{
		md5.New(),
		[]byte("abcde"),
	}

	if h.Size() != 16 {
		t.Errorf("MD5 Hash size should be 16, but was %d", h.Size())
	}
}

func TestMD5HashBlockSize(t *testing.T) {
	h := MD5Hash{
		md5.New(),
		[]byte("abcde"),
	}

	if h.BlockSize() != 64 {
		t.Errorf("MD5 Hash block size should be 64, but was %d", h.BlockSize())
	}
}

func TestStringToSign(t *testing.T) {
	expected := "&alpha=Fish _ Chips&beta=space to grow&theta=a_b+c"
	params := url.Values{}
	params.Add("beta", "space to grow")
	params.Add("alpha", "Fish & Chips")
	params.Add("theta", "a=b+c")
	actual := stringToSign(params)
	if actual != expected {
		t.Errorf("Values not equal - Actual: %s, Expected: %s", actual, expected)
	}
}

func TestGenerateSignature(t *testing.T) {
	params := url.Values{}
	params.Set("beta", "space to grow")
	params.Set("alpha", "Fish & Chips")
	params.Set("theta", "a=b+c")

	GenerateSignature(params, []byte("abcde"), MD5_HASH)
	if params.Get("timestamp") == "" {
		t.Error("GenerateSignature should add a timestamp!")
	}
	existingTimestamp := params.Get("timestamp")

	GenerateSignature(params, []byte("abcde"), MD5_HASH)
	if params.Get("timestamp") != existingTimestamp {
		t.Error("New timestamp added when one was already in params!")
	}
}

func TestGenerateSignatureWithMD5Hash(t *testing.T) {
	params := url.Values{}
	params.Set("beta", "space to grow")
	params.Set("alpha", "Fish & Chips")
	params.Set("theta", "a=b+c")
	params.Set("timestamp", "1000")

	sig := GenerateSignature(params, []byte("abcde"), MD5_HASH)
	expected := "c975ffc453f8f2ce77c46fee53dfb585"
	if sig != expected {
		t.Errorf("Invalid MD5 Hash signature. Should be: %s, instead: %s", expected, sig)
	}
}

func TestGenerateSignatureWithMD5HMAC(t *testing.T) {
	params := url.Values{}
	params.Set("beta", "space to grow")
	params.Set("alpha", "Fish & Chips")
	params.Set("theta", "a=b+c")
	params.Set("timestamp", "1000")

	sig := GenerateSignature(params, []byte("abcde"), MD5_HMAC)
	expected := "b957087e8f65b6be9150690c8a5fe17a"
	if sig != expected {
		t.Errorf("Invalid MD5 HMAC signature. Should be: %s, instead: %s", expected, sig)
	}
}

func TestGenerateSignatureWithSHA1HMAC(t *testing.T) {
	params := url.Values{}
	params.Set("beta", "space to grow")
	params.Set("alpha", "Fish & Chips")
	params.Set("theta", "a=b+c")
	params.Set("timestamp", "1000")

	sig := GenerateSignature(params, []byte("abcde"), SHA1_HMAC)
	expected := "ef5ce53edac220f9dd7d5fdef3d499c0c6095f36"
	if sig != expected {
		t.Errorf("Invalid SHA1 HMAC signature. Should be: %s, instead: %s", expected, sig)
	}
}

func TestGenerateSignatureWithSHA256HMAC(t *testing.T) {
	params := url.Values{}
	params.Set("beta", "space to grow")
	params.Set("alpha", "Fish & Chips")
	params.Set("theta", "a=b+c")
	params.Set("timestamp", "1000")

	sig := GenerateSignature(params, []byte("abcde"), SHA256_HMAC)
	expected := "7b70325bae59ef6cccf1e4ec82b8aa13fd197d148c60b270653f965d4bc1494b"
	if sig != expected {
		t.Errorf("Invalid SHA256 HMAC signature. Should be: %s, instead: %s", expected, sig)
	}
}

func TestGenerateSignatureWithSHA512HMAC(t *testing.T) {
	params := url.Values{}
	params.Set("beta", "space to grow")
	params.Set("alpha", "Fish & Chips")
	params.Set("theta", "a=b+c")
	params.Set("timestamp", "1000")

	sig := GenerateSignature(params, []byte("abcde"), SHA512_HMAC)
	expected := "e7e79c8087958fbbc88348be79d78fb960e45b9c67953d634590484704cda85c9ab6665915f190c46f6e4b180ef0289769b8e0e3ae0d3240377134b8365eb77a"
	if sig != expected {
		t.Errorf("Invalid SHA512 HMAC signature. Should be: %s, instead: %s", expected, sig)
	}
}

func TestGenerateSignatureWithBadMethod(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewHash on bad SignatureMethod should panic, but it didn't")
		}
	}()
	var badMethod SignatureMethod = 42

	badMethod.NewHash([]byte("this-is-irrelevant"))
}