package main

import (
	"testing"
)

func TestValidateProof(t *testing.T) {
	for _, sample := range samples() {
		ok, err := ValidateProof(sample())
		if err != nil {
			t.Error(err)
		}
		if !ok {
			t.Error("Proof validation failed")
		}
	}
}
