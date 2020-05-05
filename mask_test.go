package mask

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"reflect"
	"testing"
)

type Employee struct {
	Name        string `mask:"true"`
	Phonenumber string `mask:"true"`
}

func TestMask(t *testing.T) {
	emp := Employee{
		Name:        "test test",
		Phonenumber: "123456789",
	}

	empName := "t*** t***"
	empPhone := "123******"

	Mask(&emp)

	if emp.Name != empName {
		t.Errorf("Expected: %v , got: %v", empName, emp.Name)
	}

	if emp.Phonenumber != empPhone {
		t.Errorf("Expected: %v , got: %v", empPhone, emp.Phonenumber)
	}

}

func TestMaskAESGCM(t *testing.T) {
	emp := Employee{
		Name:        "test test",
		Phonenumber: "123456789",
	}

	empName := emp.Name
	empPhone := emp.Phonenumber

	sk := "TESTyfsdlfjlfdsoOIUIJJDSAOJ90naf"

	MaskAESGCM(&emp, sk)

	if empName != decrypt(emp.Name) {
		t.Errorf("Expected: %v, n got: %v n", empName, decrypt(emp.Name))
	}

	if empPhone != decrypt(emp.Phonenumber) {
		t.Errorf("Expected: %v, got: %v", empPhone, emp.Phonenumber)
	}

}

func TestMaskString(t *testing.T) {
	value := "test1234"

	expected := "tes*****"
	got := MaskString(value)
	if got != expected {
		t.Errorf("Expected: %v , got: %v", expected, got)
	}
}

func TestMaskField(t *testing.T) {
	emp := Employee{
		Name:        "test test",
		Phonenumber: "123456789",
	}

	empName := "t*** t***"
	empPhone := "123******"

	object1 := reflect.ValueOf(emp)
	got := MaskField(object1, 0, "", "")

	if got != empName {
		t.Errorf("Expected: %v , got: %v", empName, got)
	}

	got = MaskField(object1, 1, "", "")
	if got != empPhone {
		t.Errorf("Expected: %v , got: %v", empPhone, got)
	}

}

func TestMaskFieldAESGCM(t *testing.T) {
	emp := Employee{
		Name:        "test test",
		Phonenumber: "123456789",
	}

	sk := "TESTyfsdlfjlfdsoOIUIJJDSAOJ90naf"

	object1 := reflect.ValueOf(emp)
	got := MaskField(object1, 0, AESGCM, sk)

	if emp.Name != decrypt(got) {
		t.Errorf("Expected: %v, got: %v", emp.Name, decrypt(got))
	}

	got = MaskField(object1, 1, AESGCM, sk)
	if emp.Phonenumber != decrypt(got) {
		t.Errorf("Expected: %v, got: %v", emp.Phonenumber, got)
	}

}

func decrypt(encText string) string {
	ct, _ := hex.DecodeString(encText)
	byteText := ct
	c, err := aes.NewCipher([]byte("TESTyfsdlfjlfdsoOIUIJJDSAOJ90naf"))
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err.Error())
	}

	nonceSize := gcm.NonceSize()
	if len(byteText) < nonceSize {
		return ""
	}
	nonce, byteText := byteText[:nonceSize], byteText[nonceSize:]
	s, err := gcm.Open(nil, nonce, byteText, nil)
	if err != nil {
		panic(err.Error())
	}
	return string(s[:])
}
