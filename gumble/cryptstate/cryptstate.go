// Copyright (c) 2010-2020 The Grumble Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// This file is adapted from Grumble's cryptstate implementation.  It retains
// Mumble's legacy OCB2-AES128 wire format for interoperating with servers
// which use CryptSetup.
package cryptstate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

const (
	blockSize          = aes.BlockSize
	decryptHistorySize = 0x100
	overhead           = 4 // IV byte plus a three-byte OCB2 authentication tag
)

// State encrypts and decrypts legacy Mumble UDP packets. Its methods are safe
// for one concurrent reader and one concurrent writer.
type State struct {
	mu sync.Mutex

	block     cipher.Block
	key       []byte
	encryptIV []byte
	decryptIV []byte
	history   [decryptHistorySize]byte

	Good, Late, Lost, Resync uint32
	LastGoodTime             time.Time
}

// SetKey initializes State using the key and directional IVs in CryptSetup.
// encryptIV is the client nonce and decryptIV is the server nonce.
func (s *State) SetKey(key, encryptIV, decryptIV []byte) error {
	if len(key) != blockSize || len(encryptIV) != blockSize || len(decryptIV) != blockSize {
		return errors.New("gumble: CryptSetup must contain 16-byte key and nonces")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = b
	s.key = append(s.key[:0], key...)
	s.encryptIV = append(s.encryptIV[:0], encryptIV...)
	s.decryptIV = append(s.decryptIV[:0], decryptIV...)
	s.history = [decryptHistorySize]byte{}
	s.Good, s.Late, s.Lost, s.Resync = 0, 0, 0, 0
	return nil
}

// Ready reports whether the state has been initialized by CryptSetup.
func (s *State) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.block != nil
}

// Overhead is the number of bytes added to an encrypted packet.
func (s *State) Overhead() int { return overhead }

// Encrypt returns a complete legacy Mumble UDP ciphertext.
func (s *State) Encrypt(plain []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.block == nil {
		return nil, errors.New("gumble: UDP crypt state is not initialized")
	}
	for i := range s.encryptIV {
		s.encryptIV[i]++
		if s.encryptIV[i] != 0 {
			break
		}
	}
	ciphertext := make([]byte, len(plain)+overhead)
	ciphertext[0] = s.encryptIV[0]
	ocbEncrypt(s.block, ciphertext[1+3:], plain, s.encryptIV, ciphertext[1:4])
	return ciphertext, nil
}

// Decrypt authenticates and decrypts a complete legacy Mumble UDP packet.
func (s *State) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < overhead {
		return nil, errors.New("gumble: UDP packet is shorter than its crypt overhead")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.block == nil {
		return nil, errors.New("gumble: UDP crypt state is not initialized")
	}

	savedIV := append([]byte(nil), s.decryptIV...)
	ivByte := ciphertext[0]
	restore := false
	lost, late := 0, 0

	if byte(s.decryptIV[0]+1) == ivByte {
		if ivByte > s.decryptIV[0] {
			s.decryptIV[0] = ivByte
		} else if ivByte < s.decryptIV[0] {
			s.decryptIV[0] = ivByte
			increment(s.decryptIV)
		} else {
			return nil, errors.New("gumble: invalid UDP IV")
		}
	} else {
		diff := int(ivByte - s.decryptIV[0])
		if diff > 128 {
			diff -= 256
		} else if diff < -128 {
			diff += 256
		}
		switch {
		case ivByte < s.decryptIV[0] && diff > -30 && diff < 0:
			late, lost, restore = 1, -1, true
			s.decryptIV[0] = ivByte
		case ivByte > s.decryptIV[0] && diff > -30 && diff < 0:
			late, lost, restore = 1, -1, true
			s.decryptIV[0] = ivByte
			decrement(s.decryptIV)
		case ivByte > s.decryptIV[0] && diff > 0:
			lost = int(ivByte-s.decryptIV[0]) - 1
			s.decryptIV[0] = ivByte
		case ivByte < s.decryptIV[0] && diff > 0:
			lost = 256 - int(s.decryptIV[0]) + int(ivByte) - 1
			s.decryptIV[0] = ivByte
			increment(s.decryptIV)
		default:
			return nil, errors.New("gumble: UDP IV does not match packet")
		}
		if s.history[s.decryptIV[0]] == s.decryptIV[1] {
			copy(s.decryptIV, savedIV)
		}
	}

	plain := make([]byte, len(ciphertext)-overhead)
	if !ocbDecrypt(s.block, plain, ciphertext[4:], s.decryptIV, ciphertext[1:4]) {
		copy(s.decryptIV, savedIV)
		return nil, errors.New("gumble: UDP authentication tag mismatch")
	}
	s.history[s.decryptIV[0]] = s.decryptIV[1]
	if restore {
		copy(s.decryptIV, savedIV)
	}
	s.Good++
	if late > 0 {
		s.Late += uint32(late)
	} else {
		s.Late -= uint32(-late)
	}
	if lost > 0 {
		s.Lost += uint32(lost)
	} else {
		s.Lost -= uint32(-lost)
	}
	s.LastGoodTime = time.Now()
	return plain, nil
}

// EncryptIV returns a copy of the current client nonce for a CryptSetup
// resynchronization response.
func (s *State) EncryptIV() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.encryptIV...)
}

// SetDecryptIV applies a server-nonce resynchronization request.
func (s *State) SetDecryptIV(iv []byte) error {
	if len(iv) != blockSize {
		return errors.New("gumble: server nonce must be 16 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.block == nil {
		return errors.New("gumble: UDP crypt state is not initialized")
	}
	copy(s.decryptIV, iv)
	s.Resync++
	return nil
}

func increment(iv []byte) {
	for i := 1; i < len(iv); i++ {
		iv[i]++
		if iv[i] != 0 {
			return
		}
	}
}

func decrement(iv []byte) {
	for i := 1; i < len(iv); i++ {
		iv[i]--
		if iv[i] != 0xff {
			return
		}
	}
}

func xor(dst, a, b []byte) {
	for i := 0; i < blockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}
func times2(block []byte) {
	carry := (block[0] >> 7) & 1
	for i := 0; i < blockSize-1; i++ {
		block[i] = (block[i] << 1) | ((block[i+1] >> 7) & 1)
	}
	block[blockSize-1] = (block[blockSize-1] << 1) ^ (carry * 135)
}
func times3(block []byte) {
	carry := (block[0] >> 7) & 1
	for i := 0; i < blockSize-1; i++ {
		block[i] ^= (block[i] << 1) | ((block[i+1] >> 7) & 1)
	}
	block[blockSize-1] ^= (block[blockSize-1] << 1) ^ (carry * 135)
}

// ocbEncrypt and ocbDecrypt are the OCB2-AES128 primitive used by Mumble's
// legacy UDP transport.  Mumble transmits only the first three tag bytes.
func ocbEncrypt(block cipher.Block, dst, src, nonce, tag []byte) {
	var checksum, delta, tmp, pad, calculated [blockSize]byte
	block.Encrypt(delta[:], nonce)
	off, remain := 0, len(src)
	for remain > blockSize {
		times2(delta[:])
		xor(tmp[:], delta[:], src[off:off+blockSize])
		block.Encrypt(tmp[:], tmp[:])
		xor(dst[off:off+blockSize], delta[:], tmp[:])
		xor(checksum[:], checksum[:], src[off:off+blockSize])
		off += blockSize
		remain -= blockSize
	}
	times2(delta[:])
	tmp[blockSize-2] = byte((remain * 8) >> 8)
	tmp[blockSize-1] = byte(remain * 8)
	xor(tmp[:], tmp[:], delta[:])
	block.Encrypt(pad[:], tmp[:])
	copy(tmp[:], src[off:])
	copy(tmp[remain:], pad[remain:])
	xor(checksum[:], checksum[:], tmp[:])
	xor(tmp[:], pad[:], tmp[:])
	copy(dst[off:], tmp[:remain])
	times3(delta[:])
	xor(tmp[:], delta[:], checksum[:])
	block.Encrypt(calculated[:], tmp[:])
	copy(tag, calculated[:])
}

func ocbDecrypt(block cipher.Block, dst, src, nonce, tag []byte) bool {
	var checksum, delta, tmp, pad, calculated [blockSize]byte
	block.Encrypt(delta[:], nonce)
	off, remain := 0, len(src)
	for remain > blockSize {
		times2(delta[:])
		xor(tmp[:], delta[:], src[off:off+blockSize])
		block.Decrypt(tmp[:], tmp[:])
		xor(dst[off:off+blockSize], delta[:], tmp[:])
		xor(checksum[:], checksum[:], dst[off:off+blockSize])
		off += blockSize
		remain -= blockSize
	}
	times2(delta[:])
	tmp[blockSize-2] = byte((remain * 8) >> 8)
	tmp[blockSize-1] = byte(remain * 8)
	xor(tmp[:], tmp[:], delta[:])
	block.Encrypt(pad[:], tmp[:])
	tmp = [blockSize]byte{}
	copy(tmp[:remain], src[off:])
	xor(tmp[:], tmp[:], pad[:])
	xor(checksum[:], checksum[:], tmp[:])
	copy(dst[off:], tmp[:remain])
	times3(delta[:])
	xor(tmp[:], delta[:], checksum[:])
	block.Encrypt(calculated[:], tmp[:])
	return subtle.ConstantTimeCompare(calculated[:len(tag)], tag) == 1
}
