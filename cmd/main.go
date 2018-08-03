package main

import (
	"fmt"

	"github.com/millken/jwhois"
)

func main() {
	data, err := jwhois.Whois("INTERNET-BLK-A2HOS-2")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", data)
}
