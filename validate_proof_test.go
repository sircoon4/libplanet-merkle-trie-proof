package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/sircoon4/bencodex-go/bencodextype"
	"github.com/sircoon4/bencodex-go/util"
)

func TestValidateProof(t *testing.T) {
	proofInfos := parseProofInfos()
	fmt.Println("Test case count:", len(proofInfos))
	for i, proofInfo := range proofInfos {
		fmt.Println("Test case", i+1)

		proofInfoDict := proofInfo.(*bencodextype.Dictionary)

		// stateRootHash, proof, key, value
		stateRootHash := proofInfoDict.Get("stateRootHash").([]byte)
		proof := anyArrayToBytesArray(proofInfoDict.Get("proof").([]any))
		key := proofInfoDict.Get("key").([]byte)
		value := proofInfoDict.Get("value").([]byte)

		_, err := ValidateProof(stateRootHash, proof, key, value)
		if err != nil {
			t.Error(err)
		}
	}
}

func parseProofInfos() []any {
	proofInfosJsonData, err := os.ReadFile("./libplanet-block-proofs-11188814.repr.json")
	if err != nil {
		panic(err)
	}

	proofInfosBencodex, err := util.UnmarshalJsonRepr(proofInfosJsonData)
	if err != nil {
		panic(err)
	}

	return proofInfosBencodex.([]any)
}

func anyArrayToBytesArray(anyArray []any) [][]byte {
	bytesArray := make([][]byte, len(anyArray))
	for i, any := range anyArray {
		bytesArray[i] = any.([]byte)
	}
	return bytesArray
}
