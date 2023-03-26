package cert

type Cert struct {
	Path         string
	SerialNumber string
	Expires      string
}

func NewCert(Path string) *Cert {
	return &Cert{
		Path: Path,
	}
}
