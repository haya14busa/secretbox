package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/haya14busa/secretbox"
)

var key = flag.String("key", "", "secret key in hex")
var decrypt = flag.Bool("d", false, "decrypt data")

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func run() error {
	if *key == "" {
		return errors.New("-key is empty")
	}

	s, err := secretbox.NewFromHexKey(*key)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	if *decrypt {
		plaintxt, err := s.Decrypt(data)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s", plaintxt)
		return nil
	}

	ciphertext, err := s.Encrypt(data)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s", ciphertext)
	return nil
}
