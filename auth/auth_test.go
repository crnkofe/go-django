package auth

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"reflect"
	"testing"
	"time"
)

// Django's default max_age is defined as 2 weeks.
const defaultMaxAge = 14 * 24 * time.Hour

var decodeData = []struct {
	secret  string
	cookie  string
	salt    string
	fnHash  func() hash.Hash
	decoded map[string]interface{}
}{
	{
		"70e97f01975bb59ae8804ca164081c46034042aa913a4dac055cad6a7e188bd1",
		".eJyrVopPLC3JiC8tTi2Kz0xRsjI0NjbRQRZMSkzOTs0DyigV5-em6hWXp6aW6DlBBWsB4AYWwQ:1XeDSa:WrnCueUH3vz5K8cZidNGZSd-zQw",
		"django.contrib.sessions.backends.signed_cookies",
		sha1.New,
		map[string]interface{}{
			"_auth_user_backend": "some.sweet.Backend",
			"_auth_user_id":      float64(1334),
		},
	},
	{
		"d2cf3c63-e429-4dd1-8b0a-309b89963cc9",
		".eJxVjMEOwiAQRP-FsyEs0q549N5vILssSNXQpLQn47_bJj3oYS7z3sxbBVqXEtaW5jCKuiqrTr8dU3ymugN5UL1POk51mUfWu6IP2vQwSXrdDvfvoFAr27rLnI2AJYgWvTFJMIF4RPB9xLyFTHI5M4ET0zN7pAufMyB05CKpzxf2pDiH:1sgSTL:Pl3lUzok6M-dV80WxAsGfp9fGYO12SIMAy35rey1ygw",
		"django.contrib.sessions.SessionStore",
		sha256.New,
		map[string]interface{}{
			"_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
			"_auth_user_hash":    "5fbf0d12a1c27900ed7e1d977196c7f6c7a0e4ffba14d06bb97a8b3f1715a4ca",
			"_auth_user_id":      "2",
		},
	},
	{
		"d2cf3c63-e429-4dd1-8b0a-309b89963cc9",
		"eyJfYXV0aF91c2VyX2JhY2tlbmQiOiJkamFuZ28uY29udHJpYi5hdXRoLmJhY2tlbmRzLk1vZGVsQmFja2VuZCIsIl9hdXRoX3VzZXJfaWQiOjEzMzd9:1sgk7L:IBk2-Q2SDYCtznMxgLkTWBtPp9xuZKeNXzUF3aaWQ4A",
		"django.contrib.sessions.SessionStore",
		sha256.New,
		map[string]interface{}{
			"_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
			"_auth_user_id":      float64(1337),
		},
	},
	{
		"django-insecure-secret-key",
		".eJyrVopPLC3JiC8tTi2KT0pMzk7NS1GyUkrJSsxLz9dLzs8rKcpM0gMp0YPKFuv55qek5jhB1eogG5AJ1GtobGxeCwCTkB-G:1sgkAS:Td9DZldDj48WePoWWTREW1XraeYP-cvtyeMoNWhok-k",
		"django.contrib.sessions.SessionStore",
		sha256.New,
		map[string]interface{}{
			"_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
			"_auth_user_id":      float64(1337),
		},
	},
}

func TestDecode(t *testing.T) {
	now = testNowOK
	for _, d := range decodeData {
		session := NewSession(defaultMaxAge, d.secret, d.salt, d.fnHash, []byte{':'})
		decoded, err := session.Decode(d.cookie)
		if err != nil {
			t.Errorf("Decode('%s', '%s'): %s", d.secret, d.cookie, err)
			continue
		}
		expected := d.decoded
		if len(expected) != len(decoded) {
			t.Errorf("wrong len")
		}
		if !reflect.DeepEqual(expected, decoded) {
			t.Errorf("DeepEqual(%#v != %#v)", expected, decoded)
			continue
		}
	}
}

func TestLoadsJSONAllocs(t *testing.T) {
	now = testNowOK
	n := testing.AllocsPerRun(100, func() {
		d := &decodeData[1]
		session := NewSession(defaultMaxAge, d.secret, d.salt, d.fnHash, []byte{':'})
		decoded, err := session.Decode(d.cookie)
		if err != nil {
			panic(err)
		}
		_ = decoded
	})
	fmt.Printf("load allocs json: %f\n", n)
	if n > 55 {
		t.Errorf("too many (%f) allocs in loads", n)
	}
}

func testNowOK() time.Time {
	t, _ := time.Parse("2006-01-02", "2014-10-15")
	return t
}

func testNowTimedOut() time.Time {
	t, _ := time.Parse("2006-01-02", "2014-11-15")
	return t
}

func TestCookieTimeout(t *testing.T) {
	now = testNowTimedOut
	d := &decodeData[0]
	session := NewSession(defaultMaxAge, d.secret, d.salt, d.fnHash, []byte{':'})
	_, err := session.Decode(d.cookie)
	if err == nil {
		t.Errorf("should fail to decode, but doesn't")
	}
}

var base62Data = []struct {
	encoded string
	decoded int64
}{
	{"d5778337", 137633489102557},
	{"d5778349", 137633489102621},
}

func TestBase62Decode(t *testing.T) {
	for _, d := range base62Data {
		n, err := b62Decode([]byte(d.encoded))
		if err != nil {
			t.Errorf("b62Decode('%s'): %s", d.encoded, err)
			continue
		}
		if n != d.decoded {
			t.Errorf("incorrect decode: %d != %d", n, d.decoded)
		}
	}
}
