package main

import (
	"testing"
)

func TestValidateProof(t *testing.T) {
	for _, sample := range samples() {
		ok, err := ValidateProof(sample())
		if err != nil {
			t.Error(err)
		} else if !ok {
			t.Error("Proof validation failed")
		} else {
			t.Log("Proof validation succeeded")
		}
	}
}
