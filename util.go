package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func loadMotd(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "Welcome to this knot!\n"
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return string(data)
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		bytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		})
		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, err
		}
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	return signer, nil
}
