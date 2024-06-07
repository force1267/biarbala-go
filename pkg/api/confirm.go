package api

import (
	"biarbala/pkg/project"
	"io"
	"net/http"
)

func ConfirmProject(w http.ResponseWriter, r *http.Request) {
	projectName := r.URL.Query().Get("project")
	if projectName == "" {
		status := http.StatusBadRequest
		errorText := http.StatusText(status) + ": provide a 'project' query parameter with project's name"
		http.Error(w, errorText, status)
		return
	}

	project, err := project.Load(projectName)
	if err != nil {
		status := http.StatusBadRequest
		errorText := http.StatusText(status) + ": " + err.Error()
		http.Error(w, errorText, status)
		return
	}

	err = project.Confirm()
	if err != nil {
		status := http.StatusUnauthorized
		errorText := http.StatusText(status) + ": " + err.Error()
		http.Error(w, errorText, status)
		return
	}

	io.WriteString(w, "confirmed "+project.Name)
}
