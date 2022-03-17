package main

import (
	"github.com/Under-the-third-year-of-university/network-information-security/first/rsa/rsa"
)

func main() {
	//rsaClient1 := rsa.GenerateKey(1024)
	//rsaClient1.SaveKeys("./")
	rsaClient, _ := rsa.LoadKeys("./")
	err := rsaClient.SaveEncryptResult("./en.txt", "./en_res.txt")
	if err != nil {
		return
	}
	err = rsaClient.SaveDecryptResult("./en_res.txt", "./de_res.txt")
	if err != nil {
		return
	}
	//res := rsaClient.Encrypt("陈wk@")
	//for _, item := range res {
	//	fmt.Println(item)
	//}
	//res2 := rsaClient.Decrypt(res)
	//fmt.Println(strings.Join(res2, ""))
}
