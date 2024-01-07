# 💥 Shrapnel
Explode and implode nested encoding


# Example

[example/example.go](example/example.go)

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	shrapnel "github.com/B00TK1D/shrapnel"
)

func main() {

	// Open input.txt and read the contents
	f, err := os.Open("input.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	input, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	// Create a new shrapnel object
	original := shrapnel.Fragment{
		Contents: input,
	}

	// Explode the input
	original.Explode(shrapnel.AllExploders...)

	// Print the original signature
	//original.Print()
	fmt.Printf("Original signature:\t%x\n", original.Signature)

	//fmt.Println("----------------------------------------------------")

	// Apply a converter that changes "user" to "newthing"
	original.Apply(func(input []byte) []byte {
		return bytes.ReplaceAll(input, []byte("triple"), []byte("quadruple"))
	})

	// Print the results
	//original.Print()

	// Implode the input
	original.Implode()

	fmt.Println("----------------------------------------------------")

	original.Print()

	fmt.Println("----------------------------------------------------")

	fmt.Println(string(original.Contents))

	// Print the results
	fmt.Println(string(original.Contents))
	fmt.Printf("New signature:\t\t%x\n", original.Signature)
}

```
