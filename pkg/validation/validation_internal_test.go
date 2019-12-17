package validation

import "testing"

func TestStringInArray(t *testing.T) {
	var array = []string{"a", "b", "c"}

	// exist in array tests
	if !stringInSlice("a", array) {
		t.Error("String \"a\" should be in array")
	}

	if !stringInSlice("b", array) {
		t.Error("String \"b\" should be in array")
	}

	if !stringInSlice("c", array) {
		t.Error("String \"c\" should be in array")
	}

	// not in array tests
	if stringInSlice("not in array", array) {
		t.Error("Input string is not supposed to be in array")
	}

	if stringInSlice("ab", array) {
		t.Error("Input string is not supposed to be in array")
	}
}
