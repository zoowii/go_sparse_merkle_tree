package go_sparse_merkle_tree

import (
	"fmt"
	"math/big"
	"testing"
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
	fmt.Printf("tx3 proof: %s\n", BytesToHex(tx3Proof))
	fmt.Printf("tree root: %s\n", BytesToHex(smt.Root.Bytes()))
	tree2 := NewEmptySMT(DefaultSMTDepth)
	tx3VerifyResult := tree2.Verify(big.NewInt(303), []byte("tx3"), smt.Root.Bytes(), tx3Proof)
	fmt.Printf("tx3 verify result: %v\n", tx3VerifyResult)
}
