package main

import (
	"fmt"

	"github.com/B00TK1D/shrapnel/pkg/shrapnel"
)

func main() {
	// Create a new particle
	p := shrapnel.Particle{
		contents: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nDate: Wed, 03 Jan 2024 07:12:24 GMT\r\nContent-Type: application/json\r\nContent-Length: 253\r\nConnection: keep-alive\r\nSet-Cookie: session=eyJ1c2VybmFtZSI6ICI5bVR5cmpsTmluQ1M3MHNpejlsTyIsICJ1c2VyX2lkIjogMjMxMjQsICJzYWx0ZWRfaGFzaCI6ICI4M2JmZjhhZDY4NTNkZWYyY2JhYjFhMTEwODVhNzcwMjljNjIzMDY1NWQ1ODhkNzQzMDAxYTlmNzcwYzU3NGM3In0=; Path=/\r\n\r\n{\"cookie\":\"eyJ1c2VybmFtZSI6ICI5bVR5cmpsTmluQ1M3MHNpejlsTyIsICJ1c2VyX2lkIjogMjMxMjQsICJzYWx0ZWRfaGFzaCI6ICI4M2JmZjhhZDY4NTNkZWYyY2JhYjFhMTEwODVhNzcwMjljNjIzMDY1NWQ1ODhkNzQzMDAxYTlmNzcwYzU3NGM3In0=\",\"id\":23124,\"status\":\"ok\",\"user\":\"9mTyrjlNinCS70siz9lO\"}\r\nWXpJNWRGcFlVbTloVnpWdVNVaFNlV0ZZUW5OYVUwSnNZbTFPZGxwSFZtcz0="),
	}

	// Explode the particle
	p.Explode([]shrapnel.Exploder{
		shrapnel.Base64Exploder,
		shrapnel.HexExploder,
		shrapnel.HTTPHeaderExploder,
	})

	// Implode the particle
	p.Implode()

	// Print the contents of the particle
	fmt.Println(string(p.Contents))
}
