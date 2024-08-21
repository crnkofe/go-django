go-django - work with Django data in Go
=======================================

go-django is a utility for decoding Django sessions.

This is a fork of https://github.com/bpowers/go-django modified to support latest (5.0+) Django signed sessions.

usage
-----

First, `go get` it:

    $ go get github.com/crnkofe/go-django/...


Then import and use:

```Go
package main

import (
	"encoding/json"
	"fmt"
	"github.com/crnkofe/go-django/auth"
	"log"
	"os"
)

const secretKey = "django-insecure-secret-key"

func decodeSession(cookie string) (map[string]interface{}, error) {
	session := auth.NewDefaultSession(secretKey)
	return session.Decode(cookie)
}

func main() {
	if len(os.Args) <= 1 {
		fmt.Println("usage: cmd <cookie>")
		os.Exit(0)
	}

	data, err := decodeSession(os.Args[1])
	if err != nil {
		log.Printf("failed decoding session: %v\n", err)
		os.Exit(1)
	}

	decodedSession, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		log.Printf("failed marshalling session data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(decodedSession))
}
```

For a working session value make use of: `.eJyrVopPLC3JiC8tTi2KT0pMzk7NS1GyUkrJSsxLz9dLzs8rKcpM0gMp0YPKFuv55qek5jhB1eogG5AJ1GtobGxeCwCTkB-G:1sgkAS:Td9DZldDj48WePoWWTREW1XraeYP-cvtyeMoNWhok-k`

license
-------

go-django is offered under the MIT license, see LICENSE for details.
