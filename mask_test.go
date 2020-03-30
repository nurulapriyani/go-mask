package mask

import (
	"reflect"
	"testing"
)

type Employee struct {
	Name      string `mask:"true"`
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
	got := MaskField(object1, 0)

	if got != empName {
		t.Errorf("Expected: %v , got: %v", empName, got)
	}

	got = MaskField(object1, 1)
	if got != empPhone {
		t.Errorf("Expected: %v , got: %v", empPhone, got)
	}

}
