package rsa

import (
	"math/big"
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

func (r *RSA) Init(size int64) {
	n, e, d := r.generateKey(size)

	r.privateKey.n = n
	r.publicKey.n = n
	r.privateKey.d = d
	r.publicKey.e = e
}

func (r *RSA) generateKey(size int64) (*big.Int, *big.Int, *big.Int) {
	p, q := bigPrime(size), bigPrime(size)
	//p, q := bigPrime2(size), bigPrime2(size)

	var n = big.NewInt(0)
	n.Add(n, p)
	n.Mul(n, q)

	var standard = big.NewInt(1)

	var qlow = big.NewInt(0)
	qlow.Add(qlow, q)
	qlow.Sub(q, standard)

	var plow = big.NewInt(0)
	plow.Add(plow, q)
	plow.Sub(p, standard)

	var pqmo = big.NewInt(2)
	pqmo.Mul(plow, qlow)

	var e = big.NewInt(2)
	e.Lsh(e, uint(size-1))

	for ; ; e.Add(e, standard) {
		var temp = big.NewInt(0)
		temp.Add(temp, e)
		temp.GCD(nil, nil, temp, pqmo)
		if temp.Cmp(standard) == 0 {
			break
		}
	}

	var d = big.NewInt(0)
	d.ModInverse(e, pqmo)

	return n, e, d
}

func (r *RSA) Decrypt(message []*big.Int) []string {
	res := make([]string, 0)

	for _, item := range message {
		tmp := big.NewInt(0)
		tmp.Exp(item, r.privateKey.d, r.privateKey.n)
		res = append(res, string(tmp.Int64()))
	}
	return res
}

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
