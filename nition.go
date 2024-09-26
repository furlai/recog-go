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
	DatabasesByMatchKey map[string][]*FingerprintDB
	Logger              *log.Logger
}

// NewFingerprintSet returns an allocated FingerprintSet structure
func NewFingerprintSet() *FingerprintSet {
	fs := &FingerprintSet{}
	fs.DatabasesByMatchKey = make(map[string][]*FingerprintDB)
	return fs
}

// MatchFirst matches data to a given fingerprint database
func (fs *FingerprintSet) MatchFirst(name string, data string) (*FingerprintMatch, error) {
	if fdbs, ok := fs.DatabasesByMatchKey[name]; ok {
		return fdbs[0].MatchFirst(data), nil
	}

	return nil, fmt.Errorf("database %s is missing", name)
}

// MatchAll matches data to a given fingerprint database
func (fs *FingerprintSet) MatchAll(name string, data string) ([]*FingerprintMatch, error) {
	if fdbs, ok := fs.DatabasesByMatchKey[name]; ok {
		var matches []*FingerprintMatch
		for _, fdb := range fdbs {
			matches = append(matches, fdb.MatchAll(data)...)
		}
		return matches, nil
	}

	return nil, fmt.Errorf("database %s is missing", name)
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
		fs.DatabasesByMatchKey[fdb.Matches] = append(fs.DatabasesByMatchKey[fdb.Matches], &fdb)

		// also add the alias by its name
		fs.DatabasesByMatchKey[fdb.Name] = append(fs.DatabasesByMatchKey[fdb.Name], &fdb)
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
