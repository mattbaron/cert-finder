package main

import (
	"fmt"

	"github.com/mattbaron/cert-finder/finder"
)

func main() {
	finder := finder.NewFinder(".crt", ".cer", ".pem", ".der", ".pfx", ".p12", ".cert")
	//finder := finder.NewFinder(".der")
	finder.FindFiles("/Users/mbaron/nas/certs")

	for _, file := range finder.Files {
		for _, cert := range file.Certs {
			fmt.Printf("File: %s, Expires: %s\n", file.Path, cert.NotAfter)
		}
	}
}
