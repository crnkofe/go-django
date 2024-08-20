package signedcookie

import (
	"reflect"
	"testing"
	"time"
)

const testSalt = "django.contrib.sessions.backends.signed_cookies"

var decodeData = []struct {
	kind    Serializer
	secret  string
	cookie  string
	decoded map[string]interface{}
}{
	{
		JSON,
		"70e97f01975bb59ae8804ca164081c46034042aa913a4dac055cad6a7e188bd1",
		".eJyrVopPLC3JiC8tTi2Kz0xRsjI0NjbRQRZMSkzOTs0DyigV5-em6hWXp6aW6DlBBWsB4AYWwQ:1XeDSa:WrnCueUH3vz5K8cZidNGZSd-zQw",
		map[string]interface{}{
			"_auth_user_backend": "some.sweet.Backend",
			"_auth_user_id":      float64(1334),
		},
	},
}

func TestDecode(t *testing.T) {
	now = testNowOK
	for _, d := range decodeData {
		decoded, err := Decode(d.kind, DefaultMaxAge, d.secret, d.cookie, testSalt)
		if err != nil {
			t.Errorf("Decode(%d, '%s', '%s'): %s", d.kind, d.secret, d.cookie, err)
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
	_, err := Decode(d.kind, DefaultMaxAge, d.secret, d.cookie, testSalt)
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
