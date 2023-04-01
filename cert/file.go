package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

type File struct {
	Path  string
	Ext   string
	Data  []byte
	Certs []*x509.Certificate
}

func NewFile(Path string) *File {
	file := &File{
		Path:  Path,
		Certs: make([]*x509.Certificate, 0),
		Ext:   filepath.Ext(Path),
	}

	if strings.Contains(file.Ext, "p12") {
		file.LoadP12()
	} else {
		file.LoadPem()
	}

	fmt.Printf("FILE: %s, CERTS: %d\n", file.Path, len(file.Certs))

	return file
}

func (f *File) AddCert(c *x509.Certificate) {
	f.Certs = append(f.Certs, c)
}

func (f *File) LoadP12() error {
	bytes, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}

	_, cert, err := pkcs12.Decode(bytes, "")
	if err == nil {
		f.AddCert(cert)
	} else {
		fmt.Println(err)
	}

	return nil
}

func (f *File) LoadPem() error {

	bytes, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}

	for more := true; more; {
		block, rest := pem.Decode(bytes)

		if block == nil {
			more = false
			continue
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				f.Certs = append(f.Certs, cert)
			}
		}

		bytes = rest
		more = (len(rest) > 0)
	}

	return nil
}
