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
	fmt.Println(string(original.Flatten()))
	fmt.Printf("New signature:\t\t%x\n", original.Signature)

	fmt.Printf("\n\n\n")

	// Open 2 input files
	f1, err := os.Open("input1.txt")
	if err != nil {
		panic(err)
	}
	defer f1.Close()
	input1, err := io.ReadAll(f1)
	if err != nil {
		panic(err)
	}

	f2, err := os.Open("input2.txt")
	if err != nil {
		panic(err)
	}
	defer f2.Close()
	input2, err := io.ReadAll(f2)
	if err != nil {
		panic(err)
	}

	// Create 2 new shrapnel objects
	original1 := shrapnel.Fragment{
		Contents: input1,
	}
	original2 := shrapnel.Fragment{
		Contents: input2,
	}

	// Explode the inputs
	original1.Explode(shrapnel.AllExploders...)
	original2.Explode(shrapnel.AllExploders...)

	// Print their signatures
	fmt.Printf("Original 1 signature:\t%x\n", original1.Signature)
	fmt.Printf("Original 2 signature:\t%x\n", original2.Signature)

	fmt.Printf("%s\n", original1.Flatten())
	fmt.Printf("%s\n", original2.Flatten())

	fmt.Println("----------------------------------------------------")

	// Find differences between the two inputs
	result, err := shrapnel.Parallel(func(inputs [][]byte) []byte {
		for _, input := range inputs {
			if !bytes.Equal(input, inputs[0]) {
				return append(append(inputs[0], []byte(" >>>>>>>> ")...), input...)
			}
		}
		return []byte{}
	}, original1, original2)
	if err != nil {
		panic(err)
	}

	// Print the results
	for _, r := range result {
		fmt.Println(string(r))
	}

}
