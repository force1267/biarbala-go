package confirmdomain

import (
	"net"
)

func Confirm(domain string, key string) (bool, error) {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return false, err
	}

	for _, txt := range txts {
		if txt == key {
			return true, nil
		}
	}

	return false, nil
}
