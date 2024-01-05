# 💥 Shrapnel
Explode and implode nested encoding


# Example

[example/example.go](example/example.go)

```go
package main

import (
	"bytes"
	"fmt"

	shrapnel "github.com/B00TK1D/shrapnel"
)

func main() {
	original := shrapnel.Fragment{
		Contents: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nDate: Wed, 03 Jan 2024 07:12:24 GMT\r\nContent-Type: application/json\r\nContent-Length: 308\r\nConnection: keep-alive\r\nSet-Cookie: session=eyJ1c2VybmFtZSI6ICI5bVR5cmpsTmluQ1M3MHNpejlsTyIsICJ1c2VyX2lkIjogMjMxMjQsICJzYWx0ZWRfaGFzaCI6ICI4M2JmZjhhZDY4NTNkZWYyY2JhYjFhMTEwODVhNzcwMjljNjIzMDY1NWQ1ODhkNzQzMDAxYTlmNzcwYzU3NGM3In0=; Path=/\r\n\r\n{\"cookie\":\"eyJ1c2VybmFtZSI6ICI5bVR5cmpsTmluQ1M3MHNpejlsTyIsICJ1c2VyX2lkIjogMjMxMjQsICJzYWx0ZWRfaGFzaCI6ICI4M2JmZjhhZDY4NTNkZWYyY2JhYjFhMTEwODVhNzcwMjljNjIzMDY1NWQ1ODhkNzQzMDAxYTlmNzcwYzU3NGM3In0=\",\"id\":WXpJNWRGcFlVbTloVnpWdVNVaFNlV0ZZUW5OYVUwSnNZbTFPZGxwSFZtcz0=,\"status\":\"ok\",\"user\":\"9mTyrjlNinCS70siz9lO\"}\r\n"),
	}

	// Explode the input
	original.Explode(shrapnel.HttpHeaderExploder, shrapnel.Base64Exploder, shrapnel.HexExploder, shrapnel.JsonExploder)

	// Print the results
	original.Print()

	fmt.Println("----------------------------------------------------")

	// Apply a converter that changes "user" to "newthing"
	original.Apply(func(input []byte) []byte {
		return bytes.ReplaceAll(input, []byte("user"), []byte("newthing"))
	})

	// Apply a converter that changes "hash" to "otherhash"
	original.Apply(func(input []byte) []byte {
		return bytes.ReplaceAll(input, []byte("hash"), []byte("otherhash"))
	})

	// Print the results
	original.Print()

	fmt.Println("----------------------------------------------------")

	// Implode the input
	original.Implode()

	// Print the results
	fmt.Println(string(original.Contents))
}
```
