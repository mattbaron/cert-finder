package main

import (
	"fmt"
	"time"

	"github.com/mattbaron/cert-finder/finder"
	"github.com/mattbaron/cert-finder/influx"
)

func main() {
	finder := finder.NewFinder(".crt", ".cer", ".pem", ".der", ".pfx", ".p12", ".cert")
	//finder := finder.NewFinder(".der")
	finder.FindFiles("/Users/mbaron/nas/certs")

	now := time.Now()

	for _, file := range finder.Files {
		for _, cert := range file.Certs {

			line := influx.NewLine("cert-finder")
			line.AddTag("host", "foobar")
			line.AddTag("location", file.Path)
			line.AddField("expire_days", cert.NotAfter.Sub(now).Hours()/24)

			fmt.Println(line)
		}
	}
}
