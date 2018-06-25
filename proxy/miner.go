package proxy

import (
	"log"
	"math/big"
	"strconv"
	"strings"
	"bytes"
	"testing"
	"encoding/binary"

	"github.com/sammy007/open-ethereum-pool/cryptonight"
	"github.com/ethereum/ethash"
	"github.com/ethereum/go-ethereum/common"
)

var hasher = ethash.New()

func TestHashBytes(t *testing.T) {
        var b [1024]byte
        r1 := cryptonight.HashBytes(b[:])
        r2 := cryptonight.HashBytes(b[:])
        if ! bytes.Equal(r1[:], r2[:]) {
                t.Fail()
        }
}

// cryptonight hash function for new proof-of-work, no more mixing is added, modified by ZorroII
func hashcryptonight(hash []byte, nonce uint64) ([]byte, []byte) {

        //seed := make([]byte, 40)
        seed := make([]byte, 48) //fixed by toints
        copy(seed, hash)
        //binary.LittleEndian.PutUint64(seed[32:], nonce)
        /*   
        *     seed in memory:
        *     hash      | \0x00    | nonce
        *     ----------|----------|------
        *     32 bytes  | 8 bytes  | 8 bytes
        */
        binary.LittleEndian.PutUint64(seed[40:], nonce) //fixed by toints
        digest := cryptonight.HashBytes(seed)
        //ethash, the pow of ethereum is a heavy calculation, ethereum use a mixhash=sha256(headerhash+digest)
        //to prevent ddos attack. cryptonight is not so heavy and sha256 is not cpu friendly, so we remove this thing.
        //the mixhash in header is just digest of header+nonce
        return digest, digest
}

func (s *ProxyServer) processShare(login, id, ip string, t *BlockTemplate, params []string) (bool, bool) {
	nonceHex := params[0]
	hashNoNonce := params[1]
	mixDigest := params[2]
	nonce, _ := strconv.ParseUint(strings.Replace(nonceHex, "0x", "", -1), 16, 64)
	shareDiff := s.config.Proxy.Difficulty

	maxUint256 := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

	h, ok := t.headers[hashNoNonce]
	if !ok {
		log.Printf("Stale share from %v@%v", login, ip)
		return false, false
	}

	share := Block{
		number:      h.height,
		hashNoNonce: common.HexToHash(hashNoNonce),
		difficulty:  big.NewInt(shareDiff),
		nonce:       nonce,
		mixDigest:   common.HexToHash(mixDigest),
	}

	block := Block{
		number:      h.height,
		hashNoNonce: common.HexToHash(hashNoNonce),
		difficulty:  h.diff,
		nonce:       nonce,
		mixDigest:   common.HexToHash(mixDigest),
	}
	log.Printf("%+v",shareDiff);
	log.Printf("%#v,", h.diff);

	log.Printf("%+x", share);
	log.Printf("%#v", share);
	log.Printf("%+x", block);
	log.Printf("%#v", block);

        digest,mix := hashcryptonight(share.hashNoNonce.Bytes(), share.nonce);

	if bytes.Equal(digest, mix) {}

	if !bytes.Equal(block.mixDigest.Bytes(), digest){
		log.Printf("digest incorrect!");
		return false, false
	}

	targetShare := new(big.Int).Div(maxUint256, share.difficulty)
	if new(big.Int).SetBytes(digest).Cmp(targetShare) <= 0 {
		log.Printf("share accepted")
	}else{
		return false, false
	}
	//if !hasher.Verify(share) { return false, false }

	targetBlock := new(big.Int).Div(maxUint256, block.difficulty)
	if new(big.Int).SetBytes(digest).Cmp(targetBlock) <= 0 {
	//if hasher.Verify(block) {
		ok, err := s.rpc().SubmitBlock(params)
		if err != nil {
			log.Printf("Block submission failure at height %v for %v: %v", h.height, t.Header, err)
		} else if !ok {
			log.Printf("Block rejected at height %v for %v", h.height, t.Header)
			return false, false
		} else {
			s.fetchBlockTemplate()
			exist, err := s.backend.WriteBlock(login, id, params, shareDiff, h.diff.Int64(), h.height, s.hashrateExpiration)
			if exist {
				return true, false
			}
			if err != nil {
				log.Println("Failed to insert block candidate into backend:", err)
			} else {
				log.Printf("Inserted block %v to backend", h.height)
			}
			log.Printf("Block found by miner %v@%v at height %d", login, ip, h.height)
		}
	} else {
		exist, err := s.backend.WriteShare(login, id, params, shareDiff, h.height, s.hashrateExpiration)
		if exist {
			return true, false
		}
		if err != nil {
			log.Println("Failed to insert share data into backend:", err)
		}
	}
	return false, true
}
