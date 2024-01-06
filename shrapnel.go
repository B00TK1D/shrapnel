package shrapnel

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"regexp"
)

type Signature []byte

type Extractor func([]byte) ([][]byte, Signature)

type Transformer struct {
	Transform func([]byte) []byte
	Reverse   func([]byte) []byte
}

type Filter func([]byte) bool

type Exploder struct {
	Extract     Extractor
	Transformer Transformer
	Filter      Filter
}

type Fragment struct {
	children  []*Fragment
	Signature Signature
	Contents  []byte
	original  []byte
	source    Transformer
}

func (e *Fragment) Explode(exploders ...Exploder) {
	e.Signature = Signature{}
	for exploderIndex, exploder := range exploders {
		extracts, signature := exploder.Extract(e.Contents)
		for _, extracted := range extracts {
			Transformed := exploder.Transformer.Transform(extracted)
			if exploder.Filter(Transformed) {
				child := Fragment{
					Contents: Transformed,
					original: extracted,
					source:   exploder.Transformer,
				}
				child.Explode(exploders...)
				e.children = append(e.children, &child)
				signature.append(child.Signature)
			}
		}
		if len(extracts) > 0 {
			e.Signature.append(Signature{byte(exploderIndex)})
			e.Signature.append(signature)
		}
	}
}

func (e *Fragment) Implode() {
	for _, child := range e.children {
		child.Implode()
		if child.source.Reverse == nil {
			continue
		}
		e.Contents = bytes.ReplaceAll(e.Contents, child.original, child.source.Reverse(child.Contents))
	}
}

func (e *Fragment) Apply(visitor func([]byte) []byte) {
	e.Contents = visitor(e.Contents)
	for _, child := range e.children {
		child.Apply(visitor)
	}
}

func (e *Fragment) Print() {
	fmt.Printf("%x: %s\n", e.Signature, string(e.Contents))
	for _, child := range e.children {
		child.Print()
	}
}

func (s *Signature) append(appended ...Signature) {
	combinedLength := len(*s)
	for _, append := range appended {
		combinedLength += len(append)
	}
	combined := make([]byte, combinedLength)
	combinedIndex := len(*s)
	copy(combined[0:len(*s)], *s)
	for _, append := range appended {
		copy(combined[combinedIndex:], append[:])
		combinedIndex += len(append)
	}
	hash := md5.Sum(combined)
	*s = hash[:]
}

func TransformerFactory(t interface{}, r interface{}) Transformer {
	return Transformer{
		Transform: TransformerGenerator(t),
		Reverse:   TransformerGenerator(r),
	}
}

func TransformerGenerator(Transform interface{}) func([]byte) []byte {
	switch Transformer := Transform.(type) {
	case func([]byte) ([]byte, error):
		return func(input []byte) []byte {
			Transformed, err := Transformer(input)
			if err != nil {
				return []byte{}
			}
			return Transformed
		}
	case func(string) (string, error):
		return func(input []byte) []byte {
			Transformed, err := Transformer(string(input))
			if err != nil {
				return []byte{}
			}
			return []byte(Transformed)
		}
	case func(string) ([]byte, error):
		return func(input []byte) []byte {
			Transformed, err := Transformer(string(input))
			if err != nil {
				return []byte{}
			}
			return Transformed
		}
	case func([]byte) string:
		return func(input []byte) []byte {
			Transformed := Transformer(input)
			return []byte(Transformed)
		}
	case func([]byte) []byte:
		return func(input []byte) []byte {
			Transformed := Transformer(input)
			return Transformed
		}
	case func(string) string:
		return func(input []byte) []byte {
			Transformed := Transformer(string(input))
			return []byte(Transformed)
		}
	case func(string) []byte:
		return func(input []byte) []byte {
			Transformed := Transformer(string(input))
			return Transformed
		}
	case func([]byte) (string, error):
		return func(input []byte) []byte {
			Transformed, err := Transformer(input)
			if err != nil {
				return []byte{}
			}
			return []byte(Transformed)
		}
	}
	return func(input []byte) []byte {
		return input
	}
}

func regexExtractorGenerator(regex string) Extractor {
	return func(input []byte) ([][]byte, Signature) {
		return regexp.MustCompile(regex).FindAll(input, -1), Signature{}
	}
}

func FilterChainGenerator(Filters ...Filter) Filter {
	return func(input []byte) bool {
		for _, Filter := range Filters {
			if !Filter(input) {
				return false
			}
		}
		return true
	}
}
