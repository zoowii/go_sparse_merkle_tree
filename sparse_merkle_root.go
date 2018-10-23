package go_sparse_merkle_tree

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sort"
)

// uint256 help functions
type Uint256 = *big.Int

func Uint256Add(a Uint256, b Uint256) Uint256 {
	result := big.NewInt(0)
	result = result.Add(a, b)
	return result
}

func Uint256Sub(a Uint256, b Uint256) Uint256 {
	result := big.NewInt(0)
	result = result.Sub(a, b)
	return result
}

func Uint256Div(value Uint256, other Uint256) Uint256 {
	result := big.NewInt(0)
	result = result.Div(value, other)
	return result
}

func Uint256Mod(value Uint256, other Uint256) Uint256 {
	result := big.NewInt(0)
	m := big.NewInt(0)
	result, m = result.DivMod(value, other, m)
	return m
}

func Uint256Pow(value Uint256, e Uint256) Uint256 {
	result := big.NewInt(0)
	result = result.Exp(value, e, nil)
	return result
}

// uint256 keys
type Uint256Keys struct {
	container []Uint256
}

func NewUint256Keys() *Uint256Keys {
	keys := new(Uint256Keys)
	keys.container = make([]Uint256, 0)
	return keys
}

func (keys *Uint256Keys) Len() int {
	return len(keys.container)
}

func (keys *Uint256Keys) Get(idx int) (Uint256, bool) {
	if idx < 0 || idx >= len(keys.container) {
		return nil, false
	}
	return keys.container[idx], true
}

//该方法中，比较两个元素值的操作全权交给了compareFunc字段所代表的那个函数
func (keys *Uint256Keys) Less(i, j int) bool {
	return keys.container[i].Cmp(keys.container[j]) < 0
}

func (keys *Uint256Keys) Swap(i, j int) {
	keys.container[i], keys.container[j] = keys.container[j], keys.container[i]
}

func (keys *Uint256Keys) Add(value Uint256) {
	for _, v := range keys.container {
		if v.Cmp(value) == 0 {
			return
		}
	}
	keys.container = append(keys.container, value)
	sort.Sort(keys)
}

// merkle tree level ordered map
type TreeItemHashValue = []byte

type TreeLevelOrderedMap struct {
	keys *Uint256Keys
	m    map[Uint256]TreeItemHashValue
}

func NewOrderedTreeLevelMap(m map[Uint256]TreeItemHashValue) *TreeLevelOrderedMap {
	tree := new(TreeLevelOrderedMap)
	tree.m = m
	tree.keys = NewUint256Keys()
	for key := range m {
		tree.keys.Add(key)
	}
	sort.Sort(tree.keys)
	return tree
}

func (omap *TreeLevelOrderedMap) Len() int {
	return omap.keys.Len()
}

func (omap *TreeLevelOrderedMap) Keys() *Uint256Keys {
	return omap.keys
}

func (omap *TreeLevelOrderedMap) Get(key Uint256) (TreeItemHashValue, bool) {
	for k, value := range omap.m {
		if k.Cmp(key) == 0 {
			return value, true
		}
	}
	return nil, false
}

func (omap *TreeLevelOrderedMap) ContainsKey(key Uint256) bool {
	for k, _ := range omap.m {
		if k.Cmp(key) == 0 {
			return true
		}
	}
	return false
}

func (omap *TreeLevelOrderedMap) Set(key Uint256, value TreeItemHashValue) {
	omap.m[key] = value
	omap.keys.Add(key)
	sort.Sort(omap.keys)
}

func (omap *TreeLevelOrderedMap) Sort() {
	sort.Sort(omap.keys)
}

// SMT tree
type HashFuncType func([]byte) Uint256

func sha256Hash(data []byte) Uint256 {
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	var result = big.NewInt(0)
	result.SetBytes(hashed)
	return result
}

type SMT struct {
	Depth        uint
	Leaves       *TreeLevelOrderedMap
	DefaultNodes []Uint256
	Tree         []*TreeLevelOrderedMap
	Root         Uint256
	HashFunc     HashFuncType
}

// DefaultSMTDepth default sparse merkle tree depth should be 64
var DefaultSMTDepth uint = 64

func NewSMT(leaves map[Uint256]TreeItemHashValue, depth uint) *SMT {
	smt := new(SMT)
	if depth <= 0 {
		return nil
	}
	smt.Depth = depth
	if uint64(len(leaves)) > ^uint64(0) {
		return nil
	}
	smt.HashFunc = sha256Hash
	smt.Leaves = NewOrderedTreeLevelMap(leaves)
	smt.DefaultNodes = smt.createDefaultNodes(depth)
	if smt.Leaves.Len() > 0 {
		smt.Tree = smt.createTree(smt.Leaves, smt.Depth, smt.DefaultNodes)
		lastLevelTree := smt.Tree[len(smt.Tree)-1]
		lastLevelTreeKeys := lastLevelTree.Keys()
		firstKey, _ := lastLevelTreeKeys.Get(0)
		rootBytes, ok := lastLevelTree.Get(firstKey)
		if !ok {
			return nil
		}
		smt.Root = big.NewInt(0)
		smt.Root.SetBytes(rootBytes)
	} else {
		smt.Tree = make([]*TreeLevelOrderedMap, 0)
		smt.Root = smt.DefaultNodes[smt.Depth]
	}
	return smt
}

func NewEmptySMT(depth uint) *SMT {
	leaves := make(map[Uint256]TreeItemHashValue)
	return NewSMT(leaves, depth)
}

func (smt *SMT) createDefaultNodes(depth uint) []Uint256 {
	defaultHash := smt.HashFunc(zeroBytes(32))
	defaultNodes := []Uint256{defaultHash}
	var level uint
	for level = 1; level <= depth; level++ {
		prevDefault := defaultNodes[level-1]
		defaultNodes = append(defaultNodes, smt.HashFunc(append(prevDefault.Bytes(), prevDefault.Bytes()...)))
	}
	return defaultNodes
}

func (smt *SMT) createTree(orderedLeaves *TreeLevelOrderedMap, depth uint, defaultNodes []Uint256) []*TreeLevelOrderedMap {
	tree := []*TreeLevelOrderedMap{orderedLeaves}
	treeLevel := orderedLeaves
	bigint2 := big.NewInt(2)
	bigint1 := big.NewInt(1)
	var level uint
	for level = 0; level < depth; level++ {
		nextLevel := NewOrderedTreeLevelMap(make(map[Uint256]TreeItemHashValue))
		treeLevelKeys := treeLevel.Keys()
		for i := 0; i < treeLevelKeys.Len(); i++ {
			index, _ := treeLevelKeys.Get(i)
			value, _ := treeLevel.Get(index)
			if Uint256Mod(index, bigint2).Uint64() == 0 {
				coIndex := Uint256Add(index, bigint1)
				coValue, coValueOk := treeLevel.Get(coIndex)
				if coValueOk {
					nextLevel.Set(Uint256Div(index, bigint2), smt.HashFunc(append(value, coValue...)).Bytes())
				} else {
					nextLevel.Set(Uint256Div(index, bigint2), smt.HashFunc(append(value, defaultNodes[level].Bytes()...)).Bytes())
				}
			} else {
				coIndex := Uint256Sub(index, bigint1)
				if !treeLevel.ContainsKey(coIndex) {
					nextLevel.Set(Uint256Div(index, bigint2), smt.HashFunc(append(defaultNodes[level].Bytes(), value...)).Bytes())
				}
			}
		}
		nextLevel.Sort()
		treeLevel = nextLevel
		tree = append(tree, treeLevel)
	}
	return tree
}

func zeroBytes(count uint) []byte {
	result := make([]byte, count)
	var i uint
	for i = 0; i < count; i++ {
		result[i] = 0
	}
	return result
}

func BytesToHex(src []byte) string {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return string(dst)
}

func (smt *SMT) CreateMerkleProof(uid Uint256) []byte {
	index := uid
	proof := make([]byte, 0)
	proofbits := big.NewInt(0)
	if len(smt.Tree) == 0 {
		return zeroBytes(32)
	}
	bigint2 := big.NewInt(2)
	bigint1 := big.NewInt(1)
	var level uint
	for level = 0; level < smt.Depth; level++ {
		var siblingIndex Uint256
		if Uint256Mod(index, bigint2).Uint64() == 0 {
			siblingIndex = Uint256Add(index, bigint1)
		} else {
			siblingIndex = Uint256Sub(index, bigint1)
		}
		index = Uint256Div(index, bigint2)
		treeLevel := smt.Tree[level]
		siblingValue, siblingOk := treeLevel.Get(siblingIndex)
		if siblingOk {
			proof = append(proof, siblingValue...)
			proofbits = Uint256Add(proofbits, Uint256Pow(bigint2, big.NewInt(int64(level))))
		}
	}
	proofBytes := proofbits.Bytes()
	if len(proofBytes) < 8 {
		proofBytes = append(zeroBytes(uint(8-len(proofBytes))), proofBytes...)
	}
	return append(proofBytes, proof...)
}

func (smt *SMT) Verify(uid Uint256, leafHash TreeItemHashValue, treeRoot TreeItemHashValue, proof []byte) bool {
	if len(proof) > 2056 {
		return false
	}
	proofbits := big.NewInt(0)
	proofbits.SetBytes(proof[0:8])
	index := uid
	p := 8
	computedHash := leafHash
	if len(leafHash) < 1 {
		computedHash = smt.DefaultNodes[len(smt.DefaultNodes)-1].Bytes()
	}
	bigint2 := big.NewInt(2)
	var proofElement []byte
	var d uint
	for d = 0; d < smt.Depth; d++ {
		if Uint256Mod(proofbits, bigint2).Uint64() == 0 {
			proofElement = smt.DefaultNodes[d].Bytes()
		} else {
			proofElement = proof[p : p+32]
			p += 32
		}
		if Uint256Mod(index, bigint2).Uint64() == 0 {
			computedHash = smt.HashFunc(append(computedHash, proofElement...)).Bytes()
		} else {
			computedHash = smt.HashFunc(append(proofElement, computedHash...)).Bytes()
		}
		proofbits = Uint256Div(proofbits, bigint2)
		index = Uint256Div(index, bigint2)
	}
	treeRootUint256 := big.NewInt(0)
	treeRootUint256.SetBytes(treeRoot)
	computedHashUint256 := big.NewInt(0)
	computedHashUint256.SetBytes(computedHash)
	return computedHashUint256.Cmp(treeRootUint256) == 0
}
