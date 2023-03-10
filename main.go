package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/mattbaron/cert-finder/finder"
	"golang.org/x/crypto/pkcs12"
)

func DoPem(File string, Data []byte) {
	block, _ := pem.Decode(Data)
	if block != nil {
		fmt.Printf("OK Pem: %s, type=%v\n", File, block.Type)
	} else {
		fmt.Printf("ERR Pem: %s\n", File)
	}
}

func DoPkcs12(File string, Data []byte) {
	_, cert, _ := pkcs12.Decode(Data, "")
	if cert != nil {
		fmt.Printf("OK Pem: %s %s\n", File, cert.NotAfter)
	} else {
		fmt.Printf("ERR Pem: %s\n", File)
	}
}

func main() {
	finder := finder.NewFinder(".crt", ".cer", ".pem", ".der", ".jks", ".pfx", ".p12", ".cert")
	for _, file := range finder.FindFiles("/Users/mbaron") {
		dat, _ := os.ReadFile(file)
		DoPem(file, dat)
		DoPkcs12(file, dat)
	}
}
