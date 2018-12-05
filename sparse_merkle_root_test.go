package go_sparse_merkle_tree

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSMT(t *testing.T) {
	var txs = make(map[Uint256]TreeItemHashValue)
	txs[big.NewInt(201)] = []byte("tx2")
	txs[big.NewInt(101)] = []byte("tx1")
	txs[big.NewInt(303)] = []byte("tx3")
	txs[big.NewInt(308)] = []byte("tx4")
	txs[big.NewInt(407)] = []byte("tx5")
	smt := NewSMT(txs, DefaultSMTDepth)
	if smt == nil {
		panic("smt create failed")
	}
	tx3Proof := smt.CreateMerkleProof(big.NewInt(303))
	fmt.Printf("tx3 proof: %s\n", BytesToHex(tx3Proof))         // tx3 proof: 0000000000000190d10d96f5d5d50f79d299bff2c49827b594ff484c7ee4dd40f7b4c...
	fmt.Printf("tree root: %s\n", BytesToHex(smt.Root.Bytes())) // tree root: 9da6c64db4a74efca5fe3c6979c992ece8fa88660f1bf8e273508612f77d9fc3
	tree2 := NewEmptySMT(DefaultSMTDepth)
	tx3VerifyResult := tree2.Verify(big.NewInt(303), []byte("tx3"), smt.Root.Bytes(), tx3Proof)
	fmt.Printf("tx3 verify result: %v\n", tx3VerifyResult) // result: true
}

func TestSMTOfPadding(t *testing.T) {
	var txs = make(map[Uint256]TreeItemHashValue)
	txHashHex := "d42d589e7753235675f6c21661a5e97c39570bd5426df26db13833fc46b3fcf7"
	slotHex := "77f11422ec16e11c"
	shouldRootHex := "46bbffcb1f1d7646515825dcc2ccb738155fe9178d9f62d387c3649025552b4b"
	println("shouldRootHex:", shouldRootHex)
	txHash, err := HexToBytes(txHashHex)
	assert.True(t, err == nil)
	txs[HexToBigInt(slotHex)] = txHash
	smt := NewSMT(txs, DefaultSMTDepth)
	if smt == nil {
		panic("smt create failed")
	}
	tx3Proof := smt.CreateMerkleProof(HexToBigInt(slotHex))
	fmt.Printf("tx3 proof: %s\n", BytesToHex(tx3Proof)) // tx3 proof: 0000000000000190d10d96f5d5d50f79d299bff2c49827b594ff484c7ee4dd40f7b4c...
	fmt.Printf("tree root: %s\n", smt.RootHex())        // tree root: 9da6c64db4a74efca5fe3c6979c992ece8fa88660f1bf8e273508612f77d9fc3
	tree2 := NewEmptySMT(DefaultSMTDepth)
	tx3VerifyResult := tree2.Verify(HexToBigInt(slotHex), txHash, smt.RootBytes(), tx3Proof)
	fmt.Printf("tx3 verify result: %v\n", tx3VerifyResult) // result: true
	assert.True(t, shouldRootHex == smt.RootHex())

}
