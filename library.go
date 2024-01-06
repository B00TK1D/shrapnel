package shrapnel

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func isHTTP(input []byte) bool {
	return regexp.MustCompile("(^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) \\/.* HTTP\\/\\d\\.\\d|HTTP\\/\\d\\.\\d [1-5]\\d{2} [A-Z]+)\r\n").Match(input)
}

////////////////////////////////////////
//////////// Exploder library //////////
////////////////////////////////////////

var AllExploders = []Exploder{
	Base64Exploder,
	HexExploder,
	HtmlEncodingExploder,
	UrlExploder,
	UrlEncodingExploder,
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

var HtmlEncodingExploder = Exploder{
	Transformer: TransformerFactory(html.UnescapeString, html.EscapeString),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`&#\d{2,};`),
}

var UrlExploder = Exploder{
	Transformer: TransformerFactory(url.PathUnescape, url.PathEscape),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract: func(input []byte) ([][]byte, Signature) {
		compiledRegex := regexp.MustCompile(`^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) (\/.*) HTTP\/(\d\.\d)`)
		matches := compiledRegex.FindAllSubmatch(input, -1)
		if len(matches) == 0 {
			return [][]byte{}, Signature{}
		}
		extracted := [][]byte{}
		signature := Signature{}
		for _, match := range matches {
			if len(match) < 4 {
				continue
			}
			// Extract each element of the path, url decode it, and append it to the extracted array
			pathElements := strings.Split(string(match[2]), "/")
			for _, pathElement := range pathElements {
				decodedElement, err := url.PathUnescape(pathElement)
				if err != nil {
					continue
				}
				extracted = append(extracted, []byte(decodedElement))
			}
			signature.append(Signature(match[1]))
			signature.append(Signature(match[3]))
		}
		return extracted, signature
	},
}

var UrlEncodingExploder = Exploder{
	Transformer: TransformerFactory(url.QueryUnescape, url.QueryEscape),
	Filter:      FilterChainGenerator(isAscii, isMinLength(4)),
	Extract:     regexExtractorGenerator(`%[A-Fa-f0-9]{2}+`),
}

var HttpHeaderExploder = Exploder{
	Transformer: TransformerFactory(nil, nil),
	Filter:      isAscii,
	Extract: func(input []byte) ([][]byte, Signature) {
		// Extract each header contents

		// Check if the input is HTTP
		if !isHTTP([]byte(input)) {
			return [][]byte{}, Signature{}
		}

		// First, split the input into headers and body
		headerBodySplit := strings.Split(string(input), "\r\n\r\n")
		if len(headerBodySplit) != 2 {
			return [][]byte{}, Signature{}
		}

		// Split the headers into individual headers
		headers := strings.Split(headerBodySplit[0], "\r\n")

		signature := Signature{}

		// Extract the header contents
		headerContents := make([][]byte, len(headers))
		for i, header := range headers {
			splitHeader := strings.Split(header, ":")
			if len(splitHeader) < 2 {
				continue
			}
			headerContents[i] = []byte(strings.Join(strings.Split(header, ":")[1:], ":"))
			signature.append(Signature([]byte(strings.Split(header, ":")[0])))
		}
		return headerContents, signature
	},
}

var JsonExploder = Exploder{
	Transformer: TransformerFactory(nil, nil),
	Filter:      isAscii,
	Extract: func(input []byte) ([][]byte, Signature) {
		var result [][]byte

		var obj map[string]interface{}
		err := json.Unmarshal(input, &obj)
		if err != nil {
			return [][]byte{}, Signature{}
		}

		signature := Signature{}

		for key, value := range obj {
			valueBytes, err := json.Marshal(value)
			if err != nil {
				continue
			}

			result = append(result, valueBytes)
			signature.append(Signature([]byte(key)))
		}

		return result, signature
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
