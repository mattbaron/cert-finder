package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/mattbaron/cert-finder/finder"
)

func main() {
	finder := finder.NewFinder(".crt", ".cer", ".pem", ".der", ".jks", ".pfx", ".p12", ".cert")
	for _, file := range finder.FindFiles("/Users/mbaron/google-cloud-sdk") {
		dat, err := os.ReadFile(file)
		if err == nil {
			fmt.Println(file)
			block, _ := pem.Decode(dat)

			if block != nil {
				fmt.Printf("Block: type=%v\n", block.Type)
			}

		}
	}
}
