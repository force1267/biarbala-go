package server

import (
	"biarbala/configs"
	"biarbala/pkg/api"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
)

func RunApiServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/upload", api.UploadProject)
	mux.HandleFunc("/confirm", api.ConfirmProject)

	addr := configs.BindAddress + ":" + strconv.Itoa(configs.Port)
	err := http.ListenAndServe(addr, mux)

	if errors.Is(err, http.ErrServerClosed) {
		log.Printf("api server closed\n")
	}

	if err != nil {
		log.Printf("error starting api server: %s\n", err)
		os.Exit(1)
	}
}
