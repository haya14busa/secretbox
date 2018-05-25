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
		ok, plaintxt := s.Decrypt(data)
		if !ok {
			return errors.New("failed to decrypt data")
		}
		fmt.Fprintf(os.Stdout, "%s", plaintxt)
		return nil
	}

	fmt.Fprintf(os.Stdout, "%s", s.Encrypt(data))
	return nil
}
