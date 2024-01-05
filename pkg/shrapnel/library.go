package shrapnel

import (
	b64 "encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
)

////////////////////////////////////////
//////////// Filter library ////////////
////////////////////////////////////////

func isAscii(input []byte) bool {
	// Check if the input is valid ascii
	for i := 0; i < len(input); i++ {
		if input[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func isMinLength(minLength int) Filter {
	return func(input []byte) bool {
		return len(input) >= minLength
	}
}

func isHTTP(input []byte) bool {
	return regexp.MustCompile("(^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) \\/.* HTTP\\/\\d\\.\\d|HTTP\\/\\d\\.\\d [1-5]\\d{2} [A-Z]+)\r\n").Match(input)
}

////////////////////////////////////////
//////////// Exploder library //////////
////////////////////////////////////////

var Base64Exploder = Exploder{
	Transformer: TransformerFactory(b64.StdEncoding.DecodeString, b64.StdEncoding.EncodeToString),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`[a-zA-Z0-9///+]+=?=?`),
}

var HexExploder = Exploder{
	Transformer: TransformerFactory(hex.DecodeString, hex.EncodeToString),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`[a-fA-F0-9]{2,}`),
}

var HttpHeaderExploder = Exploder{
	Transformer: TransformerFactory(nil, nil),
	Filter:      isAscii,
	Extract: func(input []byte) [][]byte {
		// Extract each header contents

		// Check if the input is HTTP
		if !isHTTP([]byte(input)) {
			return [][]byte{}
		}

		// First, split the input into headers and body
		headerBodySplit := strings.Split(string(input), "\r\n\r\n")
		if len(headerBodySplit) != 2 {
			return [][]byte{}
		}

		// Split the headers into individual headers
		headers := strings.Split(headerBodySplit[0], "\r\n")

		// Extract the header contents
		headerContents := make([][]byte, len(headers))
		for i, header := range headers {
			splitHeader := strings.Split(header, ":")
			if len(splitHeader) < 2 {
				continue
			}
			headerContents[i] = []byte(strings.Join(strings.Split(header, ":")[1:], ":"))
		}
		return headerContents
	},
}
