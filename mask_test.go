package logger

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

	sk := "6368616e676520746869732070617373776f726420746f206120736563726574"
	snonce := "64a9433eae7ccceee2fc0eda"

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

	sk := "6368616e676520746869732070617373776f726420746f206120736563726574"
	snonce := "64a9433eae7ccceee2fc0eda"

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
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString(encText)
	nonce, _ := hex.DecodeString("64a9433eae7ccceee2fc0eda")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}
