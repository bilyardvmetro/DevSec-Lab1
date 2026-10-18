// Hash reads a password from stdin and prints a bcrypt cost-12 hash.
package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strings"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 128), 1024)
	if !s.Scan() {
		fmt.Fprintln(os.Stderr, "read a password from stdin")
		os.Exit(1)
	}
	p := strings.TrimSuffix(s.Text(), "\r")
	if len(p) < 12 || len(p) > 72 {
		fmt.Fprintln(os.Stderr, "password must contain 12..72 bytes")
		os.Exit(1)
	}
	h, e := bcrypt.GenerateFromPassword([]byte(p), 12)
	if e != nil {
		fmt.Fprintln(os.Stderr, "hash failed")
		os.Exit(1)
	}
	fmt.Println(string(h))
}
