package unzip

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Extract(src string, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(dst, 0755)

	for _, f := range r.File {
		err := extractSingleFile(f, dst)
		if err != nil {
			return err
		}
	}

	return nil
}

func extractSingleFile(f *zip.File, dst string) error {
	zipFile, err := f.Open()
	if err != nil {
		return err
	}
	defer zipFile.Close()

	path := filepath.Join(dst, f.Name)
	if !strings.HasPrefix(path, filepath.Clean(dst)+"/") {
		return errors.New("corrupt zip: " + path)
	}

	if f.FileInfo().IsDir() {
		os.MkdirAll(path, f.Mode())
	} else {
		os.MkdirAll(filepath.Dir(path), f.Mode())
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(f, zipFile)
		if err != nil {
			return err
		}
	}
	return nil
}
