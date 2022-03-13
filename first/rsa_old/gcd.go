package rsa_old

func gcd(a, b int64) int64 {
	if a == b {
		return a
	}
	if a >= b {
		return tGcd(b, a)
	}
	return tGcd(a, b)
}

// tGcd 欧几里得求最大公约数
func tGcd(min, max int64) (maxDivisor int64) {
	//用大数对小数取余
	complement := max % min
	//余数不为零，小数作为大数,将余数作为小数，大数对小数递归求余
	if complement != 0 {
		maxDivisor = tGcd(complement, min)
	} else {
		//当余数为零，小数就是最大公约数
		maxDivisor = min
	}
	return
}

func inverseMod(a, m int64) int64 {
	if gcd(a, m) != 1 {
		return -1
	}
	var u1, u2, u3 int64 = 1, 0, a
	var v1, v2, v3 int64 = 0, 1, m
	for v3 != 0 {
		q := u3 / v3
		v1, v2, v3, u1, u2, u3 = u1-q*v1, u2-q*v2, u3-q*v3, v1, v2, v3
	}
	return u1 % m
}
