package rsa_old

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

type Secure interface {
	Decrypt(message string) []int64
	Encrypt(message []int64) string
}

type RSA struct {
	PublicKey struct {
		n int64
		d int64
	}
	PrivateKey struct {
		n int64
		e int64
	}
}

func (r *RSA) Init(size int64) {
	n, e, d := r.generateKey(size)
	r.PrivateKey.n = n
	r.PublicKey.n = n
	r.PrivateKey.e = e
	r.PublicKey.d = d
}

func (r *RSA) generateKey(size int64) (int64, int64, int64) {
	p, q := bigPrime(size), bigPrime(size)
	//fmt.Printf("-------\nP=%v\n-------\n", p)
	n := p * q
	var e int64 = 0
	for {
		base, _ := rand.Int(rand.Reader, big.NewInt(int64(math.Pow(2, float64(size-3)))))
		e = base.Int64() + int64(math.Pow(2, float64(size-3)))
		if gcd(e, (p-1)*(q-1)) == 1 {
			break
		}
	}
	d := inverseMod(e, (p-1)*(q-1))
	fmt.Println(d)
	return n, e, d
}

func (r *RSA) Decrypt(message []int64) string {
	res := make([]int64, 0)
	for _, item := range message {
		res = append(res, fastMod(item, r.PrivateKey.e, r.PrivateKey.n))
	}
	fmt.Println(res)
	return ""
}

func (r *RSA) Encrypt(message string) []int64 {
	data := []byte(message)
	res := make([]int64, 0)
	for _, item := range data {
		res = append(res, fastMod(int64(item), r.PublicKey.d, r.PublicKey.n))
	}
	return res
}
