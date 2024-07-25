package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/sircoon4/bencodex-go"
)

func keybytesToNibbles(str []byte) []byte {
	l := len(str) * 2
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	return nibbles
}

func checkProofNodeHash(
	targetHash []byte, // sha256(bencoded)
	proofData any, // bencodex type
	first bool,
) error {
	bencodedProofNode, err := bencodex.Encode(proofData)
	if err != nil {
		return err
	}

	if !first && len(bencodedProofNode) <= sha256.Size {
		return fmt.Errorf("proof node must be longer than hash size")
	}

	proofNodeHash := sha256.Sum256(bencodedProofNode)
	if !bytes.Equal(proofNodeHash[:], targetHash) {
		return fmt.Errorf("proof node hash does not match target hash")
	}

	return nil
}

func resolveToNextCandidateNode(
	proofNode node,
	nibbles []byte,
) (node, []byte, error) {
	switch proofNode := proofNode.(type) {
	case hashNode:
		hash := proofNode
		return hash, nibbles, nil
	case valueNode:
		value := proofNode
		return value, nibbles, nil
	case *shortNode:
		short := proofNode
		if len(nibbles) < len(short.Key) {
			return nil, nil, fmt.Errorf("nibbles exhausted")
		}

		if bytes.Equal(short.Key, nibbles[:len(short.Key)]) {
			return resolveToNextCandidateNode(short.Value, nibbles[len(short.Key):])
		} else {
			return nil, nil, fmt.Errorf("key mismatch")
		}
	case *fullNode:
		full := proofNode
		if len(nibbles) == 0 {
			if full.GetValue() != nil {
				return full.GetValue(), nil, nil
			} else {
				return nil, nil, fmt.Errorf("nibbles exhausted")
			}
		}
		child := full.Children[int(nibbles[0])]
		if child == nil {
			return nil, nil, fmt.Errorf("child not found")
		}
		return resolveToNextCandidateNode(child, nibbles[1:])
	}

	return nil, nil, fmt.Errorf("invalid proof node")
}
