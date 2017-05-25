package main

import (
	"fmt"
)

// Helper to (re)create the galois field values in tables.go
func main() {
	logs := make([]byte, 256)
	exps := make([]byte, 256)
	var i byte

	x := 1
	for i = 0; i < 255; i++ {
		exps[i] = byte(x)
		logs[byte(x)] = i
		x = x << 1
		if 0 != x&0x100 {
			// Unset the 8th bit and mix in 0x1d
			x = x ^ 0x11d
		}

	}
	// Can not log(0) so just set it neatly to 0
	logs[0] = 0

	fmt.Println(`package shamir

var (`)

	fmt.Println("\t// logTable provides the log(X)/log(g) at each index X")
	fmt.Print("\tlogTable = [256]uint8{\n\t\t")
	for i, log := range logs {
		fmt.Printf("0x%02x", log)
		if 255 == i {
			fmt.Println(",")
		} else if 7 == i%8 {
			fmt.Print(",\n\t\t")
		} else {
			fmt.Print(", ")
		}
	}

	fmt.Print("\t}\n\n")

	fmt.Println("\t// expTable provides the anti-log or exponentiation value")
	fmt.Println("\t// for the equivalent index")
	fmt.Printf("\texpTable = [256]uint8{\n\t\t")
	for i, exp := range exps {
		fmt.Printf("0x%02x", exp)
		if 255 == i {
			fmt.Println(",")
		} else if 7 == i%8 {
			fmt.Print(",\n\t\t")
		} else {
			fmt.Print(", ")
		}
	}
	fmt.Println("\t}\n)")
}
