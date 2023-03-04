package finder

import (
	"os"
	"strings"
)

type Finder struct {
	Root     string
	Patterns []string
	Files    []string
	MaxDepth int
}

func NewFinder(Patterns ...string) *Finder {
	return &Finder{
		Files:    make([]string, 0),
		Patterns: Patterns,
		MaxDepth: 5,
	}
}

func (finder *Finder) AddFile(File string) {
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

func (finder *Finder) FindDir(Directory string, Depth int) {
	if Depth > finder.MaxDepth {
		return
	}

	files, err := os.ReadDir(Directory)

	if err != nil {
		return
	}

	for _, file := range files {
		if file.IsDir() {
			finder.FindDir(Directory+"/"+file.Name(), Depth+1)
		} else if finder.Match(file.Name()) {
			finder.AddFile(file.Name())
		}
	}
}

func (finder *Finder) FindFiles(Root string) []string {
	finder.FindDir(Root, 0)
	return finder.Files
}
