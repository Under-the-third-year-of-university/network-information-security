package rsa

import (
	"crypto/rand"
	"math/big"
)

func bigPrime(size int64) *big.Int {
	low := big.NewInt(2)
	low.Lsh(low, uint(size-1))
	for {
		tmp, _ := rand.Int(rand.Reader, low)
		tmp.Add(tmp, low)
		if tmp.ProbablyPrime(64) {
			return tmp
		}
	}
}

func bigPrime2(size int64) *big.Int {
	for {
		tmp, _ := rand.Prime(rand.Reader, int(size))
		if tmp.ProbablyPrime(64) {
			return tmp
		}
	}
}

// func
