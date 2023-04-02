package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

type File struct {
	Path  string
	Ext   string
	Certs []*x509.Certificate
}

func NewFile(Path string) *File {
	file := &File{
		Path:  Path,
		Certs: make([]*x509.Certificate, 0),
		Ext:   filepath.Ext(Path),
	}

	if strings.Contains(file.Ext, "p12") || strings.Contains(file.Ext, "pfx") {
		file.LoadPKCS12()
	} else if strings.Contains(file.Ext, "der") || strings.Contains(file.Ext, "cer") {
		file.LoadBinary()
	} else {
		file.LoadPEM()
	}

	fmt.Printf("FILE: %s, CERTS: %d\n", file.Path, len(file.Certs))

	return file
}

func (f *File) AddCert(c *x509.Certificate) {
	f.Certs = append(f.Certs, c)
}

func (f *File) LoadPKCS12() error {
	bytes, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}

	pemBlocks, err := pkcs12.ToPEM(bytes, "")
	if err != nil {
		return err
	}

	for _, block := range pemBlocks {
		f.ProcessPEMBlock(block)
	}

	return nil
}

func (f *File) LoadBinary() error {
	bytes, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(bytes)
	if err == nil {
		f.AddCert(cert)
	}

	return err
}

func (f *File) LoadPEM() error {
	bytes, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}

	for {
		var block *pem.Block
		block, bytes = pem.Decode(bytes)
		if block == nil {
			break
		}
		f.ProcessPEMBlock(block)
	}

	return nil
}

func (f *File) ProcessPEMBlock(block *pem.Block) error {

	if block.Type != "CERTIFICATE" {
		return errors.New("block is not a certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		f.Certs = append(f.Certs, cert)
	}

	return nil
}
