package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

type File struct {
	Path string
	Data []byte
}

func NewFile(Path string) *File {
	file := &File{
		Path: Path,
	}

	file.Load()

	return file
}

func (f *File) Load() error {
	data, err := os.ReadFile(f.Path)
	if err == nil {
		f.Data = data
	}

	for {
		cert, rest := f.NextCert(data)

		data = rest
	}

	return err
}

func (f *File) NextCert(data []byte) (*x509.Certificate, []byte) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, rest
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, rest
	}

	return cert, rest
}
