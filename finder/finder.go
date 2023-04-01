package finder

import (
	"os"
	"strings"

	"github.com/mattbaron/cert-finder/cert"
)

const PathSeparator = string(os.PathSeparator)

type Finder struct {
	Root     string
	Patterns []string
	Files    []*cert.File
	MaxDepth int
}

func NewFinder(Patterns ...string) *Finder {
	return &Finder{
		Files:    make([]*cert.File, 0),
		Patterns: Patterns,
		MaxDepth: 5,
	}
}

func (finder *Finder) AddFile(File *cert.File) {
	finder.Files = append(finder.Files, File)
}

func (finder *Finder) Match(File string) bool {
	for _, pattern := range finder.Patterns {
		if strings.Contains(File, pattern) {
			return true
		}
	}
	return false
}

func (finder *Finder) DiscoverDirectory(Directory string, Depth int) {
	if Depth > finder.MaxDepth {
		return
	}

	files, err := os.ReadDir(Directory)

	if err != nil {
		return
	}

	for _, file := range files {
		if file.IsDir() {
			finder.DiscoverDirectory(Directory+PathSeparator+file.Name(), Depth+1)
		} else if finder.Match(file.Name()) {
			finder.AddFile(cert.NewFile(Directory + PathSeparator + file.Name()))
		}
	}
}

func (finder *Finder) FindFiles(Root string) []*cert.File {
	finder.DiscoverDirectory(Root, 0)
	return finder.Files
}
