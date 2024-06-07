package api

import (
	"biarbala/configs"
	"biarbala/pkg/project"
	"biarbala/tools/unzip"
	"io"
	"net/http"

	"errors"
	"log"
	"mime/multipart"
	"os"
	"path"

	"github.com/google/uuid"
)

func UploadProject(w http.ResponseWriter, r *http.Request) {
	var allowedSize = int64(configs.UplodaMaxSizeMB) << 20
	r.Body = http.MaxBytesReader(w, r.Body, allowedSize)

	err := r.ParseMultipartForm(int64(1 << 20)) // 1 MB in memory buffer
	if err != nil {
		status := http.StatusInternalServerError
		errorText := http.StatusText(status) + ": Error reading file: " + err.Error()
		http.Error(w, errorText, status)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		status := http.StatusInternalServerError
		errorText := http.StatusText(status) + ": Error reading file: " + err.Error()
		http.Error(w, errorText, status)
		return
	}
	defer file.Close()

	if header.Size > allowedSize {
		status := http.StatusRequestEntityTooLarge
		http.Error(w, http.StatusText(status), status)
		return
	}

	projectPath, err := extract(file)
	if err != nil {
		status := http.StatusInternalServerError
		errorText := http.StatusText(status) + ": Error reading file: " + err.Error()
		http.Error(w, errorText, status)
		return
	}

	project, err := project.Deploy(projectPath)
	if err != nil {
		status := http.StatusBadRequest
		errorText := http.StatusText(status) + ": Bad project structure: " + err.Error()
		http.Error(w, errorText, status)
		return
	}

	var msg = "uploaded " + project.Name

	if !project.Confiremd {
		msg = msg +
			". Please add provided TXT record to the domain then confirm." +
			"\n\tTXT:\t" + project.Txt +
			"\n\tDomain:\t" + project.Name +
			"\nthen call \n\t" + configs.Domain + "/confirm?project=" + project.Name +
			"\n"

	}
	_, err = io.WriteString(w, msg)
	if err != nil {
		log.Println("error responding to an upload request", err.Error())
	}
}

func extract(file multipart.File) (string, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	idstr := id.String()

	zipPath := path.Join(configs.ZipsDir, idstr+".zip")

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	written, err := io.Copy(zipFile, file)
	if err != nil {
		return "", err
	}
	if written == 0 {
		return "", errors.New("recieved empty file")
	}

	projectPath := path.Join(configs.ProjectsDir, idstr)
	err = unzip.Extract(zipPath, projectPath)

	if err != nil {
		return "", err
	}
	err = os.Remove(zipPath)
	if err != nil {
		log.Println("Error: unable to remove uploaded temporary zip file", err.Error())
		panic(err)
	}

	return projectPath, nil
}
