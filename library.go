package shrapnel

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/andybalholm/brotli"
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

var AllExploders = []Exploder{
	Base64Exploder,
	HexExploder,
	UrlExploder,
	HttpHeaderExploder,
	JsonExploder,
	GzipExploder,
	ZlibExploder,
	BrotiliExploder,
}

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

var UrlExploder = Exploder{
	Transformer: TransformerFactory(url.QueryUnescape, url.QueryEscape),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`%[A-Fa-f0-9]{2}+`),
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

var JsonExploder = Exploder{
	Transformer: TransformerFactory(nil, nil),
	Filter:      isAscii,
	Extract: func(input []byte) [][]byte {
		var result [][]byte

		var obj map[string]interface{}
		err := json.Unmarshal(input, &obj)
		if err != nil {
			return [][]byte{}
		}

		for _, value := range obj {
			valueBytes, err := json.Marshal(value)
			if err != nil {
				continue
			}

			result = append(result, valueBytes)
		}

		return result
	},
}

var GzipExploder = Exploder{
	Transformer: Transformer{
		Transform: func(input []byte) []byte {
			reader := bytes.NewReader(input)
			gzreader, err := gzip.NewReader(reader)
			if err != nil {
				return []byte{}
			}

			output, err := io.ReadAll(gzreader)
			if err != nil {
				return []byte{}
			}

			return output
		},
		Reverse: func(input []byte) []byte {
			var buf bytes.Buffer
			gzwriter := gzip.NewWriter(&buf)
			gzwriter.Write(input)
			gzwriter.Close()
			return buf.Bytes()
		},
	},
	Filter: FilterChainGenerator(isAscii, isMinLength(4)),
	Extract: func(input []byte) [][]byte {
		// Check if the input is gzip
		if bytes.HasPrefix(input, []byte{0x1f, 0x8b}) {
			return [][]byte{input}
		}
		return [][]byte{}
	},
}

var ZlibExploder = Exploder{
	Transformer: Transformer{
		Transform: func(input []byte) []byte {
			reader := bytes.NewReader(input)
			zreader, err := zlib.NewReader(reader)
			if err != nil {
				return []byte{}
			}

			output, err := io.ReadAll(zreader)
			if err != nil {
				return []byte{}
			}

			return output
		},
		Reverse: func(input []byte) []byte {
			var buf bytes.Buffer
			zwriter := zlib.NewWriter(&buf)
			zwriter.Write(input)
			zwriter.Close()
			return buf.Bytes()
		},
	},
	Filter: FilterChainGenerator(isAscii, isMinLength(4)),
	Extract: func(input []byte) [][]byte {
		// Check if the input is zlib
		if bytes.HasPrefix(input, []byte{0x78, 0x9c}) {
			return [][]byte{input}
		}
		return [][]byte{}
	},
}

var BrotiliExploder = Exploder{
	Transformer: Transformer{
		Transform: func(input []byte) []byte {
			reader := bytes.NewReader(input)
			breader := brotli.NewReader(reader)

			output, err := io.ReadAll(breader)
			if err != nil {
				return []byte{}
			}

			return output
		},
		Reverse: func(input []byte) []byte {
			var buf bytes.Buffer
			bwriter := brotli.NewWriter(&buf)
			bwriter.Write(input)
			bwriter.Close()
			return buf.Bytes()
		},
	},
	Filter: FilterChainGenerator(isAscii, isMinLength(4)),
	Extract: func(input []byte) [][]byte {
		// Check if the input is zlib
		if bytes.HasPrefix(input, []byte{0x78, 0x9c}) {
			return [][]byte{input}
		}
		return [][]byte{}
	},
}
