package project

import (
	"biarbala/configs"
	"errors"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

type Project struct {
	Name        string
	Path        string
	Confiremd   bool
	Txt         string
	hasPassword bool
	password    string
}

func Load(projectName string) (Project, error) {
	p := Project{}
	exists, err := Exists(projectName)
	if err != nil {
		return p, err
	}
	if !exists {
		return p, errors.New("project does not exsist: " + projectName)
	}

	p.Path = path.Join(configs.ProjectsDir, projectName)

	err = p.loadCNAMEFile()
	if err != nil {
		return p, err
	}

	err = p.loadPasswordFile()
	if err != nil {
		return p, err
	}

	err = p.loadConfirmFile()
	if err != nil {
		return p, err
	}

	if !p.Confiremd {
		err = p.loadTXTFile()
		if err != nil {
			return p, err
		}
	}
	return p, nil
}

func (project *Project) loadCNAMEFile() error {
	cnamePath := path.Join(project.Path, "CNAME")
	cnameFile, err := os.Open(cnamePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	defer cnameFile.Close()

	cname, err := io.ReadAll(cnameFile)
	if err != nil {
		return err
	}
	name := strings.Split(string(cname), "\n")[0]
	project.Name = name

	return nil
}

func (project *Project) loadPasswordFile() error {
	passwordFilePath := path.Join(project.Path, "PASSWORD")
	PasswordFile, err := os.Open(passwordFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			project.hasPassword = false
			return nil
		}
		return err
	}
	defer PasswordFile.Close()

	passwordData, err := io.ReadAll(PasswordFile)
	if err != nil {
		return err
	}
	password := strings.Split(string(passwordData), "\n")[0]
	project.password = password
	project.hasPassword = true
	return nil
}

func (project *Project) loadConfirmFile() error {
	confirmFilePath := path.Join(project.Path, "CONFIRM")
	_, err := os.Stat(confirmFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			project.Confiremd = false
			return nil
		}
		return err
	}
	project.Confiremd = true
	return nil
}

func (project *Project) loadTXTFile() error {
	txtFilePath := path.Join(project.Path, "TXT")
	txtFile, err := os.Open(txtFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		project.Txt = ""
		return nil
	}
	defer txtFile.Close()

	txtData, err := io.ReadAll(txtFile)
	if err != nil {
		return err
	}
	txt := strings.Split(string(txtData), "\n")[0]
	project.Txt = txt
	return nil
}

func Exists(name string) (bool, error) {
	if name == "" {
		log.Println("recieved an empty project name to check for existence")
		return false, nil
	}
	projectPath := path.Join(configs.ProjectsDir, name)
	_, err := os.Stat(projectPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func isSubDomain(name string) bool {
	return strings.HasSuffix(name, "."+configs.Domain)
}
