package migrations

import (
	"io/fs"
	"testing"
)

func TestFSContainsInitialMigration(t *testing.T) {
	entries, err := fs.ReadDir(FS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == "0001_initial.sql" {
			found = true
		}
	}
	if !found {
		t.Fatal("0001_initial.sql not embedded")
	}
}
