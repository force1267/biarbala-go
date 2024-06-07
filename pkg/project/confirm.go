package project

import (
	"biarbala/tools/confirmdomain"
	"errors"
	"log"
)

func (project Project) Confirm() error {
	if project.Confiremd {
		return errors.New("project is already confirmed: " + project.Name)
	}

	if project.Txt == "" {
		log.Println("expected a TXT file in the project but it was empty: ", project.Name)
		return errors.New("internal error: could not confirm using TXT")
	}

	confirmed, err := confirmdomain.Confirm(project.Name, project.Txt)
	if err != nil {
		return err
	}

	if !confirmed {
		return errors.New("expected TXT record was not on the project domain:\nDomain: " + project.Name + "\nTXT: " + project.Txt)
	}

	project.CreateConfirmFile()
	return nil
}
