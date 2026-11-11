package main

import (
	"fmt"
	"strconv"
)

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
func itoa(i int) string                 { return strconv.Itoa(i) }
