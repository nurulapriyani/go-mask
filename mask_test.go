package mask

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
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

	empName := "test*****"
	empPhone := "1234*****"

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
	snonce := ""

	MaskAESGCM(&emp, sk, snonce)

	if empName != decrypt(emp.Name) {
		t.Errorf("Expected: %v, n got: %v n", empName, decrypt(emp.Name))
	}

	if empPhone != decrypt(emp.Phonenumber) {
		t.Errorf("Expected: %v, got: %v", empPhone, emp.Phonenumber)
	}

}

func TestMaskString(t *testing.T) {
	value := "test1234"

	expected := "test****"
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

	empName := "test*****"
	empPhone := "1234*****"

	object1 := reflect.ValueOf(emp)
	got := MaskField(object1, 0, "", "", "")

	if got != empName {
		t.Errorf("Expected: %v , got: %v", empName, got)
	}

	got = MaskField(object1, 1, "", "", "")
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
	snonce := ""

	object1 := reflect.ValueOf(emp)
	got := MaskField(object1, 0, AESGCM, sk, snonce)

	if emp.Name != decrypt(got) {
		t.Errorf("Expected: %v, got: %v", emp.Name, decrypt(got))
	}

	got = MaskField(object1, 1, AESGCM, sk, snonce)
	if emp.Phonenumber != decrypt(got) {
		t.Errorf("Expected: %v, got: %v", emp.Phonenumber, got)
	}

}

func decrypt(encText string) string {
	key := []byte("TESTyfsdlfjlfdsoOIUIJJDSAOJ90naf")
	ciphertext, _ := hex.DecodeString(encText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return ""
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}
