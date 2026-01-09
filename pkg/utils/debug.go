package utils

import (
	"fmt"
)

func Dump(data any, args ...any) {
	fmt.Print(ToString(data) + " ")
	if len(args) > 0 {
		for _, arg := range args {
			fmt.Print(ToString(arg) + " ")
		}
	}
	fmt.Println("")
}
