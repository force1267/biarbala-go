package configs

import (
	"os"
	"strconv"
)

func read[T any](name string, val T) T {
	str := os.Getenv(name)
	if str == "" {
		return val
	}

	var deserialized any = val
	var err error

	switch deserialized.(type) {
	case int:
		deserialized, err = strconv.Atoi(str)
	case bool:
		deserialized, err = strconv.ParseBool(str)
	case float64:
		deserialized, err = strconv.ParseFloat(str, 64)
	case string:
		deserialized = str
	}

	if err != nil {
		return val
	}

	return deserialized.(T)
}
