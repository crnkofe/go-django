package signedcookie

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/bpowers/go-django/internal/github.com/kisielk/og-rek"
)

var decodeData = []struct {
	secret  string
	cookie  string
	decoded map[string]interface{}
}{
	{
		"70e97f01975bb59ae8804ca164081c46034042aa913a4dac055cad6a7e188bd1",
		".eJxrYKotZNQI5Y1PLC3JiC8tTi2Kz0wpZPI1Yw0VQhJLSkzOTs1LKWQOFSrOz03VKy5PTS3Rc4KIluoBAEyaGG0:1XeDNx:RIsFaf0wIba2w-wXrFz47me6Zcw",
		map[string]interface{}{
			"_auth_user_backend": "some.sweet.Backend",
			"_auth_user_id":      int64(1334),
		},
	},
}

func TestOgrekAllocs(t *testing.T) {
	d := &decodeData[0]
	c := []byte(d.cookie)
	payload := bytes.Split(c, []byte{':'})[0]
	decompress := false
	if payload[0] == '.' {
		decompress = true
		payload = payload[1:]
	}
	payload, err := b64Decode(payload)
	if err != nil {
		panic(fmt.Errorf("base64Decode('%s'): %s", string(payload), err))
	}
	if decompress {
		var r io.ReadCloser
		r, err = zlib.NewReader(bytes.NewReader(payload))
		if err != nil {
			panic(fmt.Errorf("zlib.NewReader: %s", err))
		}
		payload, err = ioutil.ReadAll(r)
		r.Close()
		if err != nil {
			panic(fmt.Errorf("ReadAll(zlib): %s", err))
		}
	}
	r := bytes.NewReader(payload)
	n := testing.AllocsPerRun(100, func() {
		if _, err := r.Seek(0, 0); err != nil {
			panic(err)
		}
		val, err := ogórek.NewDecoder(r).Decode()
		if err != nil {
			panic(fmt.Errorf("Decode: %s", err))
		}
		_ = val
	})
	fmt.Printf("ogre allocs: %f\n", n)
	if n > 34 {
		t.Errorf("too many (%f) allocs in ogrek", n)
	}
}

func TestLoadsAllocs(t *testing.T) {
	n := testing.AllocsPerRun(100, func() {
		d := &decodeData[0]
		decoded, err := Decode(d.secret, d.cookie)
		if err != nil {
			panic(err)
		}
		_ = decoded
	})
	fmt.Printf("load allocs: %f\n", n)
	if n > 70 {
		t.Errorf("too many (%f) allocs in loads", n)
	}
}

func TestDecode(t *testing.T) {
	for _, data := range decodeData {
		secret, cookie, expected := data.secret, data.cookie, data.decoded
		decoded, err := Decode(secret, cookie)
		if err != nil {
			t.Errorf("Decode('%s', '%s'): %s", secret, cookie, err)
			continue
		}
		if len(expected) != len(decoded) {
			t.Errorf("wrong len")
		}
		if !reflect.DeepEqual(expected, decoded) {
			t.Errorf("DeepEqual(%#v != %#v)", expected, decoded)
			continue
		}
	}
}
