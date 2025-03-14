package main
import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
	"io"
)
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	add_byte:=[]byte{byte(padding)}
	fmt.Printf("%d more bytes needed.\nByte added: 0x%x.\n",padding,add_byte)
	//PKCS7 Convention
	padText:= bytes.Repeat(add_byte,padding)
	return append(data,padText...)
}
func main() {
	// 24-byte key for Triple DES (3DES)
	key := []byte("1234567890abcdef12345678")
	plaintext := []byte("Lorem ipsum dolor")
	fmt.Printf("Text: %x\n",plaintext)
	paddedtext:=pad(plaintext,des.BlockSize)
	fmt.Printf("Padded: %x\n",paddedtext)
	// Encrypt the plaintext
	block,_:=des.NewTripleDESCipher(key)
	initialization_vector:=make([]byte,des.BlockSize)
	io.ReadFull(rand.Reader,initialization_vector)
	mode:=cipher.NewCBCEncrypter(block,initialization_vector)
	ciphertext:=make([]byte,len(paddedtext))
	mode.CryptBlocks(ciphertext,paddedtext)
	final_cipher:=append(initialization_vector,ciphertext...)
	fmt.Printf("Ciphertext: %x\n",ciphertext)
	fmt.Printf("IV: %x\n",initialization_vector)
	fmt.Printf("Final Cipher: %x\n",final_cipher)
	//
	cipher_text:=make([]byte,len(paddedtext))
	block_des1,_:=des.NewCipher(key[:8])
	block_des2,_:=des.NewCipher(key[8:16])
	block_des3,_:=des.NewCipher(key[16:])
	vector:=append(make([]byte,0),initialization_vector...)
	for i:=0;i<len(paddedtext);i+=des.BlockSize{
		for j:=0;j<des.BlockSize;j++{//cbc
			cipher_text[i+j]=vector[j]^paddedtext[i+j]
			// cipher_text[i+j]=paddedtext[i+j]
		}
		block_des1.Encrypt(cipher_text[i:i+des.BlockSize],cipher_text[i:i+des.BlockSize])
		block_des2.Decrypt(cipher_text[i:i+des.BlockSize],cipher_text[i:i+des.BlockSize])
		block_des3.Encrypt(cipher_text[i:i+des.BlockSize],cipher_text[i:i+des.BlockSize])
		copy(vector,cipher_text[i:i+des.BlockSize])
	}
	full_cipher:=append(initialization_vector,cipher_text...)
	fmt.Printf("3DES-CBC : %x\n",full_cipher)
	//Decrypt
	length:=len(full_cipher)
	original:=make([]byte,length)
	copy(original,full_cipher)
	//decrypt
	for i:=8;i<len(full_cipher);i+=des.BlockSize{
		block_des3.Decrypt(original[i:i+des.BlockSize],original[i:i+des.BlockSize])
		block_des2.Encrypt(original[i:i+des.BlockSize],original[i:i+des.BlockSize])
		block_des1.Decrypt(original[i:i+des.BlockSize],original[i:i+des.BlockSize])
		for j:=0;j<des.BlockSize;j++{//cbc
			original[i+j]=full_cipher[i+j-des.BlockSize]^original[i+j]
		}
	}
	fmt.Printf("Decrypted: %x\n",original)
	fmt.Printf("Original text : %s\n",original[des.BlockSize:length-int(original[length-1])])
}
