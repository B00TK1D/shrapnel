package shrapnel

import (
	"bytes"
	"fmt"
	"regexp"
)

type Extractor func([]byte) [][]byte

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
	children []*Fragment
	Contents []byte
	original []byte
	source   Transformer
}

func (e *Fragment) Explode(exploders []Exploder) {
	for _, exploder := range exploders {
		for _, Extracted := range exploder.Extract(e.Contents) {
			Transformed := exploder.Transformer.Transform(Extracted)
			if exploder.Filter(Transformed) {
				child := Fragment{
					Contents: Transformed,
					original: Extracted,
					source:   exploder.Transformer,
				}
				child.Explode(exploders)
				e.children = append(e.children, &child)
			}
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
	fmt.Println(string(e.Contents) + "\n")
	for _, child := range e.children {
		child.Print()
	}
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

func regexExtractorGenerator(regex string) func([]byte) [][]byte {
	return func(input []byte) [][]byte {
		return regexp.MustCompile(regex).FindAll(input, -1)
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
