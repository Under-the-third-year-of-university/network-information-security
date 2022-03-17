package rsa

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"strings"
)

type RSA struct {
	publicKey struct {
		n *big.Int
		e *big.Int
	}
	privateKey struct {
		n *big.Int
		d *big.Int
	}
}

func GenerateKey(size int64) *RSA {
	p, q := bigPrime(size), bigPrime(size)
	fmt.Printf("p=%v\nq=%v\n", p, q)
	//p, q := bigPrime2(size), bigPrime2(size)

	// 计算 p * q
	n := big.NewInt(0)
	n.Add(n, p)
	n.Mul(n, q)

	// 生成标准匹配项  进行类型统一
	standard := big.NewInt(1)

	// q - 1
	qlow := big.NewInt(0)
	qlow.Add(qlow, q)
	qlow.Sub(q, standard)

	// p - 1
	plow := big.NewInt(0)
	plow.Add(plow, q)
	plow.Sub(p, standard)

	// φ(n) = (p - 1) * (q - 1)
	pqmo := big.NewInt(2)
	pqmo.Mul(plow, qlow)

	// 生成 e 的基准值 范围为 2 ^ (size - 1)
	e := big.NewInt(2)
	e.Lsh(e, uint(size-1))

	// 进行迭代匹配
	for ; ; e.Add(e, standard) {
		var temp = big.NewInt(0)
		temp.Add(temp, e)
		// GCD(e, (p - 1) * (q - 1)) == 1
		temp.GCD(nil, nil, temp, pqmo)
		if temp.Cmp(standard) == 0 {
			break
		}
	}

	// d 为 e 与 φ(n) 的模反元素
	var d = big.NewInt(0)
	d.ModInverse(e, pqmo)

	return &RSA{
		publicKey: struct {
			n *big.Int
			e *big.Int
		}{
			n: n,
			e: e,
		},
		privateKey: struct {
			n *big.Int
			d *big.Int
		}{
			n: n,
			d: d,
		},
	}
}

func (r *RSA) Decrypt(message []*big.Int) []string {
	res := make([]string, 0)

	for _, item := range message {
		tmp := big.NewInt(0)
		tmp.Exp(item, r.privateKey.d, r.privateKey.n)
		res = append(res, fmt.Sprintf("%c", tmp.Int64()))
	}
	return res
}

// Encrypt 加密方法
func (r *RSA) Encrypt(message string) []*big.Int {
	data := []rune(message)

	res := make([]*big.Int, 0)
	for _, item := range data {
		temp := big.NewInt(int64(item))
		tmp := big.NewInt(0)
		tmp.Exp(temp, r.publicKey.e, r.publicKey.n)
		res = append(res, tmp)
	}
	return res
}

func (r *RSA) SaveKeys(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err := os.Mkdir(filePath, os.ModePerm)
		if err != nil {
			return err
		}
	}
	public := fmt.Sprintf("%s %s", r.publicKey.n, r.publicKey.e)
	private := fmt.Sprintf("%s %s", r.privateKey.n, r.privateKey.d)
	err := ioutil.WriteFile(path.Join(filePath, "key.pub.txt"), []byte(public), 0664)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(filePath, "key.txt"), []byte(private), 0664)
	if err != nil {
		return err
	}
	return nil
}

func LoadKeys(filePath string) (*RSA, error) {
	r := new(RSA)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, errors.New("path not exist")
	}
	public, _ := ioutil.ReadFile(path.Join(filePath, "key.pub.txt"))
	publicKeyString := string(public)
	publicKey := strings.Split(publicKeyString, " ")
	if len(publicKey) != 2 {
		return nil, errors.New("file failed")
	}
	tmpPubN := big.NewInt(0)
	tmpPubN, _ = tmpPubN.SetString(publicKey[0], 10)
	r.publicKey.n = big.NewInt(0)
	r.publicKey.n = r.publicKey.n.Add(r.publicKey.n, tmpPubN)

	tmpPubE := big.NewInt(0)
	tmpPubE, _ = tmpPubN.SetString(publicKey[1], 10)
	r.publicKey.e = big.NewInt(0)
	r.publicKey.e = r.publicKey.e.Add(r.publicKey.e, tmpPubE)

	private, _ := ioutil.ReadFile(path.Join(filePath, "key.txt"))
	privateKeyString := string(private)
	privateKey := strings.Split(privateKeyString, " ")
	if len(privateKey) != 2 {
		return nil, errors.New("file failed")
	}
	tmpPriN := big.NewInt(0)
	tmpPriN, _ = tmpPriN.SetString(privateKey[0], 10)
	r.privateKey.n = big.NewInt(0)
	r.privateKey.n = r.privateKey.n.Add(r.privateKey.n, tmpPriN)

	tmpPriD := big.NewInt(0)
	tmpPriD, _ = tmpPriD.SetString(privateKey[1], 10)
	r.privateKey.d = big.NewInt(0)
	r.privateKey.d = r.privateKey.d.Add(r.privateKey.d, tmpPriD)
	return r, nil
}

func (r *RSA) SaveEncryptResult(src, dst string) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return errors.New("path not exist")
	}
	data, _ := ioutil.ReadFile(src)
	res := r.Encrypt(string(data))

	enRes := make([]string, 0)
	for _, item := range res {
		enRes = append(enRes, fmt.Sprint(item))
	}
	err := ioutil.WriteFile(dst, []byte(strings.Join(enRes, " ")), 0644)
	if err != nil {
		return err
	}
	return nil
}

func (r *RSA) SaveDecryptResult(src, dst string) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return errors.New("path not exist")
	}
	data, _ := ioutil.ReadFile(src)
	enRes := strings.Split(string(data), " ")
	deReq := make([]*big.Int, 0)
	for _, item := range enRes {
		tmp := big.NewInt(0)
		tmp.SetString(item, 10)

		temp := big.NewInt(0)
		temp.Add(temp, tmp)
		deReq = append(deReq, temp)
	}

	deRes := r.Decrypt(deReq)

	err := ioutil.WriteFile(dst, []byte(strings.Join(deRes, "")), 0644)
	if err != nil {
		return err
	}
	return nil
}
