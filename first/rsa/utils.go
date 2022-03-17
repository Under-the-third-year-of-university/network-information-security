package rsa

import (
	"crypto/rand"
	"math/big"
)

// bigPrime 生成一个 2 ^ （size-1） ~ 2 ^（size） 的随机数
func bigPrime(size int64) *big.Int {
	low := big.NewInt(2)
	low.Lsh(low, uint(size-1))
	for {
		tmp, _ := rand.Int(rand.Reader, low)
		tmp.Add(tmp, low)
		// ProbablyPrime 使用 miller rabin 进行素数检测  （64） -> 检测次数  每次错误概率最多 1/4
		if tmp.ProbablyPrime(64) {
			return tmp
		}
	}
}

// bigPrime2 使用 crypto rand 生成一个时间线性的随机数  不会产生使用 time seed 时出现随机数重合
func bigPrime2(size int64) *big.Int {
	for {
		tmp, _ := rand.Prime(rand.Reader, int(size))
		if tmp.ProbablyPrime(64) {
			return tmp
		}
	}
}
