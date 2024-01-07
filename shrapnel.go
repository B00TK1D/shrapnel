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
	for exploderIndex, exploder := range exploders {
		extracts, signature := exploder.Extract(e.Contents)
		for _, extracted := range extracts {
			transformed := exploder.Transformer.Transform(extracted)
			if exploder.Filter(transformed) {
				child := Fragment{
					Contents: transformed,
					original: extracted,
					source:   exploder.Transformer,
				}
				e.children = append(e.children, &child)
				child.Explode(exploders...)
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

func (e *Fragment) Flatten() []byte {
	if len(e.children) == 0 {
		return e.Contents
	}
	if len(e.children) == 1 {
		return append(append(e.Contents, []byte(" >>>>>>>> ")...), e.children[0].Flatten()...)
	}
	flattened := []byte(" [[[[[[[[ ")
	added := [][]byte{}
	for _, child := range e.children {
		existing := false
		for _, add := range added {
			if bytes.Equal(add, child.Contents) {
				existing = true
				break
			}
		}
		childFlattened := child.Flatten()
		if !existing && len(childFlattened) > 0 {
			if len(added) > 0 {
				flattened = append(flattened, []byte(" ,,,,,,,, ")...)
			}
			flattened = append(flattened, childFlattened...)
			added = append(added, child.Contents)
		}
	}
	flattened = append(flattened, []byte(" ]]]]]]]] ")...)
	if len(added) == 0 {
		return e.Contents
	}
	if len(added) == 1 {
		return append(append(e.Contents, []byte(" >>>>>>>> ")...), added[0]...)
	}
	return flattened
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
	compiledRegex := regexp.MustCompile(regex)
	return func(input []byte) ([][]byte, Signature) {
		return compiledRegex.FindAll(input, -1), Signature{}
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
