package recog

//go:generate go run gen/vfsdata/main.go

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

// FingerprintSet is a collection of loaded Recog fingerprint databases
type FingerprintSet struct {
	Databases []*FingerprintDB
	Logger    *log.Logger
}

// NewFingerprintSet returns an allocated FingerprintSet structure
func NewFingerprintSet() *FingerprintSet {
	fs := &FingerprintSet{}
	fs.Databases = make([]*FingerprintDB, 0, 20)
	return fs
}

// MatchFirst matches data to a given fingerprint database
func (fs *FingerprintSet) MatchFirst(name string, data string) *FingerprintMatch {
	found := false
	for _, fdb := range fs.Databases {
		if fdb.Matches == name || fdb.Name == name {
			found = true
			return fdb.MatchFirst(data)
		}
	}

	nomatch := &FingerprintMatch{Matched: false}
	if !found {
		nomatch.Errors = append(nomatch.Errors, fmt.Errorf("database %s is missing", name))
	}
	return nomatch
}

// MatchAll matches data to a given fingerprint database
func (fs *FingerprintSet) MatchAll(name string, data string) []*FingerprintMatch {
	found := false
	var matches []*FingerprintMatch
	for _, fdb := range fs.Databases {
		if fdb.Matches == name || fdb.Name == name {
			found = true
			matches = append(matches, fdb.MatchAll(data)...)
		}
	}

	if !found {
		matches = append(matches, &FingerprintMatch{Matched: false, Errors: []error{fmt.Errorf("database %s is missing", name)}})
	}
	return matches
}

// LoadFingerprints parses the embedded Recog XML databases, returning a FingerprintSet
func (fs *FingerprintSet) LoadFingerprints() error {
	return fs.LoadFingerprintsFromFS(RecogXML)
}

// LoadFingerprintsDir parses Recog XML files from a local directory, returning a FingerprintSet
func (fs *FingerprintSet) LoadFingerprintsDir(dname string) error {
	return fs.LoadFingerprintsFromFS(http.Dir(dname))
}

// LoadFingerprintsFromFS parses an embedded Recog XML database, returning a FingerprintSet
func (fs *FingerprintSet) LoadFingerprintsFromFS(efs http.FileSystem) error {
	rootfs, err := efs.Open("/")
	if err != nil {
		return fmt.Errorf("failed to open root: %s", err.Error())
	}
	defer rootfs.Close()

	files, err := rootfs.Readdir(65535)
	if err != nil {
		return fmt.Errorf("failed to read root: %s", err.Error())
	}

	for _, f := range files {

		if !strings.Contains(f.Name(), ".xml") {
			continue
		}

		fd, err := efs.Open(f.Name())
		if err != nil {
			return fmt.Errorf("failed to open %s: %s", f.Name(), err.Error())
		}

		xmlData, err := ioutil.ReadAll(fd)
		if err != nil {
			fd.Close()
			return fmt.Errorf("failed to read %s: %s", f.Name(), err.Error())
		}
		fd.Close()

		fdb, err := LoadFingerprintDB(f.Name(), xmlData)
		if err != nil {
			return fmt.Errorf("failed to load %s: %s", f.Name(), err.Error())
		}

		fdb.Logger = fs.Logger

		// add the database
		fs.Databases = append(fs.Databases, &fdb)
	}

	return nil
}

// LoadFingerprints parses embedded Recog XML databases, returning a FingerprintSet
func LoadFingerprints() (*FingerprintSet, error) {
	res := NewFingerprintSet()
	return res, res.LoadFingerprints()
}

// LoadFingerprintsDir parses Recog XML files from a local directory, returning a FingerprintSet
func LoadFingerprintsDir(dname string) (*FingerprintSet, error) {
	res := NewFingerprintSet()
	return res, res.LoadFingerprintsDir(dname)
}

// MustLoadFingerprints loads the built-in fingerprints, panicing otherwise
func MustLoadFingerprints() *FingerprintSet {
	fset, err := LoadFingerprints()
	if err != nil {
		panic(err)
	}
	return fset
}
