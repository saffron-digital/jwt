package jwt

import (
	"strings"
	"testing"
)

// Test that signedToken is as expected. Expected values checked against jwt.io
func TestSignTokenSignature(t *testing.T) {
	tests := []struct {
		Alg      Algorithm
		Expected string
	}{
		{Alg: HmacSha256("test"), Expected: "7WslbFGojXwJbg3jav4hvqh386EdEcLOtqA__xOFeLc"},
		{Alg: HmacSha512("test"), Expected: "jNq1YuDIyd3anKEsIYEwiZ0I1JvKxsOKuvZ5PhJy0z3xzTbdlIHJ84Sr6REpR8oI71Oi7tW8Y5HCrJtuBTmTfw"},
	}
	for _, st := range tests {
		c := NewClaim()
		c.Set("iat", 1518774034)
		a := st.Alg
		signedToken, err := a.Encode(c)
		if err != nil {
			t.Fatal(err)
		}
		actual := strings.Split(signedToken, ".")[2]
		if actual != st.Expected {
			t.Fatalf("Signature does not match. Received: %s Expected: %s", actual, st.Expected)
		}
	}
}
