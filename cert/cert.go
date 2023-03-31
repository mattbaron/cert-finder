package cert

type Cert struct {
	File         File
	SerialNumber string
	Expires      string
}

func NewCert(file File) *Cert {
	cert := &Cert{
		File: file,
	}
	return cert
}

func (c *Cert) Decode() error {
	// data, err := os.ReadFile(c.Path)
	// if err != nil {
	// 	return err
	// }

	// block, rest := pem.Decode(data)
	// fmt.Println(block.Type)

	// certs, err := x509.ParseCertificates(block.Bytes)
	// if err == nil {
	// 	for _, cert := range certs {
	// 		fmt.Println(cert.NotAfter)
	// 	}
	// }

	return nil
}
