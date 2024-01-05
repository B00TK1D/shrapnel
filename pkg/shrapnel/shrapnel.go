package shrapnel

import (
	"bytes"
	"fmt"
	"regexp"
)

type Extractor func([]byte) [][]byte

type Transformer struct {
	transform func([]byte) []byte
	reverse   func([]byte) []byte
}

type Filter func([]byte) bool

type Exploder struct {
	extract     Extractor
	transformer Transformer
	filter      Filter
}

type Particle struct {
	children []*Particle
	contents []byte
	original []byte
	source   Transformer
}

func (e *Particle) explode(exploders []Exploder) {
	for _, exploder := range exploders {
		for _, extracted := range exploder.extract(e.contents) {
			transformed := exploder.transformer.transform(extracted)
			if exploder.filter(transformed) {
				child := Particle{
					contents: transformed,
					original: extracted,
					source:   exploder.transformer,
				}
				child.explode(exploders)
				e.children = append(e.children, &child)
			}
		}
	}
}

func (e *Particle) implode() {
	for _, child := range e.children {
		child.implode()
		if child.source.reverse == nil {
			continue
		}
		e.contents = bytes.ReplaceAll(e.contents, child.original, child.source.reverse(child.contents))
	}
}

func (e *Particle) apply(visitor func([]byte) []byte) {
	e.contents = visitor(e.contents)
	for _, child := range e.children {
		child.apply(visitor)
	}
}

func (e *Particle) print() {
	fmt.Println(string(e.contents) + "\n")
	for _, child := range e.children {
		child.print()
	}
}

func transformerFactory(t interface{}, r interface{}) Transformer {
	return Transformer{
		transform: transformerGenerator(t),
		reverse:   transformerGenerator(r),
	}
}

func transformerGenerator(transform interface{}) func([]byte) []byte {
	switch transformer := transform.(type) {
	case func([]byte) ([]byte, error):
		return func(input []byte) []byte {
			transformed, err := transformer(input)
			if err != nil {
				return []byte{}
			}
			return transformed
		}
	case func(string) (string, error):
		return func(input []byte) []byte {
			transformed, err := transformer(string(input))
			if err != nil {
				return []byte{}
			}
			return []byte(transformed)
		}
	case func(string) ([]byte, error):
		return func(input []byte) []byte {
			transformed, err := transformer(string(input))
			if err != nil {
				return []byte{}
			}
			return transformed
		}
	case func([]byte) string:
		return func(input []byte) []byte {
			transformed := transformer(input)
			return []byte(transformed)
		}
	case func([]byte) []byte:
		return func(input []byte) []byte {
			transformed := transformer(input)
			return transformed
		}
	case func(string) string:
		return func(input []byte) []byte {
			transformed := transformer(string(input))
			return []byte(transformed)
		}
	case func(string) []byte:
		return func(input []byte) []byte {
			transformed := transformer(string(input))
			return transformed
		}
	case func([]byte) (string, error):
		return func(input []byte) []byte {
			transformed, err := transformer(input)
			if err != nil {
				return []byte{}
			}
			return []byte(transformed)
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

func filterChainGenerator(filters ...Filter) Filter {
	return func(input []byte) bool {
		for _, filter := range filters {
			if !filter(input) {
				return false
			}
		}
		return true
	}
}
