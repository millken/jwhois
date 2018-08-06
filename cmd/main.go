package main

import (
	"fmt"

	"github.com/millken/jwhois"
)

func main() {
	data, err := jwhois.Whois("278")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", data)
}
