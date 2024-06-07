package project

import (
	"biarbala/configs"
	"errors"
	"os"
	"path"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/google/uuid"
)

func Deploy(projectPath string) (Project, error) {
	basename := path.Base(projectPath)
	p, err := Load(basename)
	if err != nil {
		return p, err
	}

	if p.Name == "" {
		err := p.createCNAMEFile()
		if err != nil {
			return p, err
		}
	}

	validatedPassword, err := p.validatePassword()
	if err != nil {
		return p, err
	}
	if !validatedPassword {
		return p, errors.New("could not validate using password")
	}

	err = p.validateDomain()
	if err != nil {
		return p, err
	}

	err = p.move()
	if err != nil {
		return p, err
	}

	return p, nil
}

func (project *Project) move() error {
	from := project.Path
	to := path.Join(configs.ProjectsDir, project.Name)

	alreadyExsits, err := Exists(project.Name)
	if err != nil {
		return err
	}

	if alreadyExsits {
		err = os.RemoveAll(to)
		if err != nil {
			return err
		}
	}

	err = os.Rename(from, to)
	if err != nil {
		return err
	}

	project.Path = to
	return nil
}

func (project *Project) validateDomain() error {
	originalProjectName := project.Name

	if isSubDomain(originalProjectName) {
		err := project.CreateConfirmFile()
		return err
	}

	originaProjectExists, err := Exists(originalProjectName)
	if err != nil {
		return err
	}
	if !originaProjectExists {
		err = project.initDomainConfirmationUsingTXT()
		return err
	}

	originalProject, err := Load(project.Name)
	if err != nil {
		return err
	}

	if !originalProject.Confiremd {
		err = project.initDomainConfirmationUsingTXT()
		return err
	}

	err = project.CreateConfirmFile()
	return err
}

func (project *Project) CreateConfirmFile() error {
	confirmFilePath := path.Join(project.Path, "CONFIRM")

	_, err := os.Create(confirmFilePath)
	if err != nil {
		return err
	}

	project.Confiremd = true
	return nil
}

func (project *Project) initDomainConfirmationUsingTXT() error {
	txtFilePath := path.Join(project.Path, "TXT")
	txtFile, err := os.Create(txtFilePath)
	if err != nil {
		project.Txt = ""
		return nil
	}
	defer txtFile.Close()

	id, err := uuid.NewUUID()
	if err != nil {
		return err
	}
	txtData := id.String()

	_, err = txtFile.WriteString(txtData)
	if err != nil {
		return err
	}

	project.Txt = txtData
	project.Confiremd = false

	return nil
}

func (project *Project) validatePassword() (bool, error) {
	originalProjectName := project.Name
	originaProjectExists, err := Exists(originalProjectName)
	if err != nil {
		return false, err
	}
	if !originaProjectExists {
		return true, nil
	}

	originalProject, err := Load(project.Name)
	if err != nil {
		return false, err
	}

	if !originalProject.hasPassword {
		return true, nil
	}

	if !project.hasPassword {
		return false, nil
	}

	if originalProject.password != project.password {
		// TODO Refactor: use something like hash(salt+password)
		return false, nil
	}

	return true, nil
}

func (project *Project) createCNAMEFile() error {
	cnamePath := path.Join(project.Path, "CNAME")
	cnameFile, err := os.Create(cnamePath)
	if err != nil {
		return err
	}
	defer cnameFile.Close()

	for i := 0; i < 10; i++ {
		if i == 9 {
			return errors.New("could not create random name")
		}
		name := petname.Generate(configs.ProjectRandomNameLen, "-")
		cname := name + "." + configs.Domain
		project.Name = cname
		sameNameExists, err := Exists(project.Name)
		if err != nil {
			return err
		}
		if !sameNameExists {
			break
		}
	}

	_, err = cnameFile.Write([]byte(project.Name))
	if err != nil {
		return err
	}

	return nil
}
