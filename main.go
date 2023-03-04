package main

import (
	"fmt"

	"github.com/mattbaron/cert-finder/finder"
)

func main() {
	finder := finder.NewFinder(".rb", ".json")
	for _, file := range finder.FindFiles("/Users/mbaron/git") {
		fmt.Println(file)
	}
}
