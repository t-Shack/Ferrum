package crypto

// GenerateID returns a simple identifier string built from a prefix and a number.
// This is a placeholder we will replace with real crypto in v3.
func GenerateID(prefix string, n int) string {
	if n < 0 {
		n = 0
	}
	return prefix + "_" + itoa(n)
}

// itoa converts an integer to a string without importing strconv.
// We implement it ourselves here purely for practice.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
