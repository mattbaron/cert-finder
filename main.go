package main

import (
	"encoding/pem"
	"fmt"

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
		fmt.Printf("OK Pkcs12: %s %s\n", File, cert.NotAfter)
	} else {
		fmt.Printf("ERR Pkcs12: %s\n", File)
	}
}

func main() {
	finder := finder.NewFinder(".crt", ".cer", ".pem", ".der", ".jks", ".pfx", ".p12", ".cert")
	finder.FindFiles("/Users/mbaron/tmp/certs")
}
