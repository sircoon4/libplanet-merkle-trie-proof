package main

import (
	"encoding/hex"
	"fmt"

	"github.com/sircoon4/bencodex-go"
)

// stateRootHash []byte => sha256(bencoded)
// proof [][]byte => bencoded list
// key []byte => []byte
// value []byte => bencoded

func sample00() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
	}

	key, _ = hex.DecodeString("00")

	// V00
	value, _ = hex.DecodeString("75323a3030")

	return
}

func sample01() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	proof = [][]byte{
		proofR,
		proof0,
	}

	key, _ = hex.DecodeString("01")

	// V01
	value, _ = hex.DecodeString("75323a3031")

	return
}

func sample0000() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
	}

	key, _ = hex.DecodeString("0000")

	// V0000
	value, _ = hex.DecodeString("75343a30303030")

	return
}

func sample0010() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	// ProofNode001
	proof001, _ := hex.DecodeString("6c313a0033323ab16b9db1bce3fedf7dd114b02938f2476c21936a3f30fffecc8db14d377d3dd965")
	// ProofNode0010
	proof0010, _ := hex.DecodeString("6c6e7533323a303030303030303030303030303030303030303030303030303030303030313065")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
		proof001,
		proof0010,
	}

	key, _ = hex.DecodeString("0010")

	// V0010
	value, _ = hex.DecodeString("7533323a3030303030303030303030303030303030303030303030303030303030303130")

	return
}

// Wrong hash
func sampleFalseHash() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// HalfTrieHash
	stateRootHash, _ = hex.DecodeString("6cc5c2ca1b7b146268f0d930c58c7e5441b807e72cf16d56f52c869a594b17bf")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
	}

	key, _ = hex.DecodeString("00")

	// V00
	value, _ = hex.DecodeString("75323a3030")

	return
}

// Wrong value
func sampleFalseValue() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
	}

	key, _ = hex.DecodeString("00")

	// V01
	value, _ = hex.DecodeString("75323a3031")

	return
}

// Wrong key
func sampleFalseKey() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
	}

	key, _ = hex.DecodeString("01")

	// V00
	value, _ = hex.DecodeString("75323a3030")

	return
}

// Wrong proof
func sampleFalseProof() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	// FullTrieHash
	stateRootHash, _ = hex.DecodeString("979a00921d42d2ca63e98c1c2ac07f0eacbb99e363b8f2f7f8e4d19c854b6c20")

	// ProofRoot
	proofR, _ := hex.DecodeString("6c313a0033323a84cac50effba60ce08415ff3356839fa032a91658a7740d60ffba4af6245a0c565")
	// ProofNode0
	proof0, _ := hex.DecodeString("6c33323ab7ba99008cd22b95a8fce03c7d2d72ca2352732ad0a849b91653b12ab07cce4c6c6e75323a3031656e6e6e6e6e6e6e6e6e6e6e6e6e6e6e65")
	// ProofNode00
	proof00, _ := hex.DecodeString("6c6c313a006c6e75343a30303030656533323a3edb1a2151507f2c3853e1b3a8039ec5768b22e71c268f49d12addbb6806b3f16e6e6e6e6e6e6e6e6e6e6e6e6e6e6c6e75323a30306565")
	proof = [][]byte{
		proofR,
		proof0,
		proof00,
	}

	key, _ = hex.DecodeString("01")

	// V01
	value, _ = hex.DecodeString("75323a3031")

	return
}

func sampleFromLibConsole() (stateRootHash []byte, proof [][]byte, key []byte, value []byte) {
	stateRootHash, _ = hex.DecodeString("1bb0734cffb2226288fbb5124e560deb3322a0957a710829082d25e51872c84d")

	proofData, _ := hex.DecodeString("6c6c6e6e6e33323aa05901b256bc5c70e94b294c6d8bd9446d2d7f9cb47645a5869afb779f1054176e6e6e6e6e6e6e6e6e6e6e6e6c6e6c6939656565656c323a010333323acd7c05916ad1c68c19fa275a7409ec15a2af3dcf13ffe1b4b3fa03a5e4885c99656c33323a730d10e492580dc2b071e0a2462f9a28b90be9d275e0a44711965afee77d5e316e33323a3322fd72c0ad2c681e715b82b5ac5395710510e24a70baa2fb4fb037cf6227186e6e6e6e6e6e6e6e6e6e6e6e6e6e656c37363a0307060206030306030103090603030106030309030703080605060506050306030303090303060303070308030406060605060203010605060403030306030606050604030003090306060633323ab592c07326758348b4cbf4be9be98d028381d4251308785859f7148ba333aedb656c6e33323ac606a553d2e65a72cbb8ea34dcadf14d65a3c4d8cda8ff7368cd6c35a12e7fe06565")
	bParsed, _ := bencodex.Decode(proofData)
	fmt.Println(bParsed)

	proof = [][]byte{}
	for _, p := range bParsed.([]interface{}) {
		encoded, err := bencodex.Encode(p)
		if err != nil {
			panic(err)
		}
		proof = append(proof, encoded)
	}

	key, _ = hex.DecodeString("127bc619c1c978eee6393c784feb1ed366ed096f")
	key = addressToStateKey(key)

	value, _ = hex.DecodeString("33323ac606a553d2e65a72cbb8ea34dcadf14d65a3c4d8cda8ff7368cd6c35a12e7fe0")

	return
}

func addressToStateKey(address []byte) []byte {
	conversionTable := []byte{
		48,  // '0'
		49,  // '1'
		50,  // '2'
		51,  // '3'
		52,  // '4'
		53,  // '5'
		54,  // '6'
		55,  // '7'
		56,  // '8'
		57,  // '9'
		97,  // 'a'
		98,  // 'b'
		99,  // 'c'
		100, // 'd'
		101, // 'e'
		102, // 'f'
	}

	buffer := make([]byte, len(address)*2)
	for i := 0; i < len(address); i++ {
		buffer[i*2] = conversionTable[address[i]/16]
		buffer[i*2+1] = conversionTable[address[i]%16]
	}

	return buffer
}
