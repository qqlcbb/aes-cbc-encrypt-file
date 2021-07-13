package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
)

func main() {
	encFlag := flag.Bool("e", false, "encrypt")
	decFlag := flag.Bool("d", false, "decrypt")

	flag.Parse()
	filename := flag.Arg(0)

	// 使用常量密码做demo
	key := bytes.Repeat([]byte("1"), 32)
	if *encFlag {
		outFilename, err := encryptFile(key, filename, "")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Encrypted output file:", outFilename)
	} else if *decFlag {
		outFilename, err := decryptFile(key, filename, "")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Decrypted output file:", outFilename)
	} else {
		fmt.Println(flag.Usage)
		os.Exit(1)
	}
}

// decryptFile 使用给定的密钥加密指定的文件，并输出新文件
func encryptFile(key []byte, filename string, outFilename string) (string, error) {
	if len(outFilename) == 0 {
		outFilename = filename + ".enc"
	}

	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	of, err := os.Create(outFilename)
	if err != nil {
		return "", err
	}
	defer of.Close()

	// 如果原文长度不是16字节的倍数(如果刚好是16 的倍数，也需要填充16个)
	// 使用PKCS#7填充方式去填充
	// 缺几个字节就填几个缺的字节数
	bytesToPad := aes.BlockSize
	if len(plaintext) % aes.BlockSize != 0 {
		//  需要填充的数目
		bytesToPad = aes.BlockSize - (len(plaintext) % aes.BlockSize)
	}
	// 生成填充字节数组，每个填充的字节内容为缺的字节数
	padding := bytes.Repeat([]byte{byte(bytesToPad)}, bytesToPad)
	plaintext = append(plaintext, padding...)

	// 生成IV向量写入到输出的文件中，固定是开头的16字节长度
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	if _, err = of.Write(iv); err != nil {
		return "", err
	}

	// 密文与填充后的明文大小相同
	ciphertext := make([]byte, len(plaintext))

	//  使用 cipher.Block 接口的 AES 实现来加密整个文件
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	if _, err = of.Write(ciphertext); err != nil {
		return "", err
	}
	return outFilename, nil
}

// decryptFile 使用给定的密钥解密由文件名指定的文件
func decryptFile(key []byte, filename string, outFilename string) (string, error) {
	if len(outFilename) == 0 {
		outFilename = filename + ".dec"
	}

	ciphertext, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	of, err := os.Create(outFilename)
	if err != nil {
		return "", err
	}
	defer of.Close()

	buf := bytes.NewReader(ciphertext)

	// ciphertext 在前 16 个字节中是IV，剩余部分为实际的密文
	iv := make([]byte, aes.BlockSize)
	if _, err = buf.Read(iv); err != nil {
		return "", err
	}

	// 密文的长度为加密文件内容长度减去Iv长度
	// 密文肯定是16字节的倍数，因为加密的时候有做过填充
	paddedSize := len(ciphertext) - aes.BlockSize
	if paddedSize % aes.BlockSize != 0 {
		return "", fmt.Errorf("密文错误")
	}

	plaintext := make([]byte, paddedSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext[aes.BlockSize:])

	// 减去填充的数量，获取到真正的明文长度
	bufLen := len(plaintext) - int(plaintext[len(plaintext)-1])

	if _, err := of.Write(plaintext[:bufLen]); err != nil {
		return "", err
	}
	// 输出文件
	return outFilename, nil
}