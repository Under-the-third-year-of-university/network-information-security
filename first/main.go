package main

import (
	"fmt"
	"github.com/Under-the-third-year-of-university/network-information-security/first/rsa/rsa"
	"strings"
)

func main() {
	rsaClient := rsa.RSA{}
	rsaClient.Init(64)
	res := rsaClient.Encrypt("阿斯顿 asd @ Asd")
	fmt.Println(res)
	res2 := rsaClient.Decrypt(res)
	fmt.Println(strings.Join(res2, ""))
}
