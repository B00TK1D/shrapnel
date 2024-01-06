package shrapnel

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	b64 "encoding/base64"
	"encoding/hex"
	"html"
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

var httpHeaderRegex = regexp.MustCompile(`((GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) \/.* HTTP\/\d\.\d|HTTP\/\d\.\d [1-5]\d{2} [A-Z]+)(?:.|\r\n)*?\r\n\r\n`)
var jsonRegex = regexp.MustCompile(`({(?:[^{}]|{}|{[^{}]*})+})`)

////////////////////////////////////////
//////////// Exploder library //////////
////////////////////////////////////////

var AllExploders = []Exploder{
	HttpHeaderExploder,
	GzipExploder,
	ZlibExploder,
	BrotiliExploder,
	JsonExploder,
	Base64Exploder,
	HexExploder,
	HtmlExploder,
	UrlExploder,
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

var HtmlExploder = Exploder{
	Transformer: TransformerFactory(html.UnescapeString, html.EscapeString),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`&#\d{2,};`),
}

var UrlExploder = Exploder{
	Transformer: TransformerFactory(url.QueryUnescape, url.QueryEscape),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`%[A-Fa-f0-9]{2}`),
}

var HttpHeaderExploder = Exploder{
	Transformer: TransformerFactory(nil, nil),
	Filter:      isAscii,
	Extract: func(input []byte) ([][]byte, Signature) {
		// Extract all http messages
		signature := Signature{}
		headerContents := [][]byte{}
		messages := httpHeaderRegex.FindAll([]byte(input), -1)

		for _, message := range messages {
			headers := strings.Split(string(message), "\r\n")

			for i, header := range headers {
				if i == 0 {
					// First line - treat differently
					if strings.HasPrefix(header, "HTTP") {
						// Response, use the entire line as the signature
						signature.append(Signature([]byte(header)))
					} else {
						// Request, use the method and HTTP version as the signature
						signature.append(Signature([]byte(strings.Split(header, " ")[0])))
						signature.append(Signature([]byte(strings.Split(header, " ")[2])))
					}
					continue
				}

				splitHeader := strings.Split(header, ":")
				if len(splitHeader) < 2 {
					continue
				}
				signature.append(Signature([]byte(strings.Split(header, ":")[0])))
				headerContents = append(headerContents, []byte(strings.Join(strings.Split(header, ":")[1:], ":")))
			}
		}

		return headerContents, signature
	},
}

var JsonExploder = Exploder{
	Transformer: TransformerFactory(nil, nil),
	Filter:      isAscii,
	Extract: func(input []byte) ([][]byte, Signature) {
		var contents [][]byte
		signature := Signature{}

		// Extract all json objects
		objects := jsonRegex.FindAll(input, -1)

		keyRegex := regexp.MustCompile(`"([^"]+)"\s*:\s*`)
		valueRegex := regexp.MustCompile(`\s*:\s*"?(.+?)"?\s*(?:,|})`)

		// Extract keys and values for each json object
		for _, object := range objects {
			keys := keyRegex.FindAllSubmatch(object, -1)
			values := valueRegex.FindAllSubmatch(object, -1)
			for _, key := range keys {
				signature.append(Signature(key[1]))
			}
			for _, value := range values {
				if len(value) < 2 {
					continue
				}
				if value[1][0] == '[' || value[1][0] == '{' {
					// Nested object, skip (necessary because golang doesn't support negative lookahead)
					continue
				}
				contents = append(contents, value[1])
			}
		}

		return contents, signature
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
	Extract: func(input []byte) ([][]byte, Signature) {
		// Check if the input is gzip
		if bytes.HasPrefix(input, []byte{0x1f, 0x8b}) {
			return [][]byte{input}, Signature{}
		}
		return [][]byte{}, Signature{}
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
	Extract: func(input []byte) ([][]byte, Signature) {
		// Check if the input is zlib
		if bytes.HasPrefix(input, []byte{0x78, 0x9c}) {
			return [][]byte{input}, Signature{}
		}
		return [][]byte{}, Signature{}
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
	Extract: func(input []byte) ([][]byte, Signature) {
		// Check if the input is zlib
		if bytes.HasPrefix(input, []byte{0x78, 0x9c}) {
			return [][]byte{input}, Signature{}
		}
		return [][]byte{}, Signature{}
	},
}
