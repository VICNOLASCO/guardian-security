package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type ClaveResponse struct {
	Success        bool   `json:"success"`
	ClaveBase64    string `json:"clave_base64"`
	IVBase64       string `json:"iv_base64"`
	NombreOriginal string `json:"nombre_original"`
	Error          string `json:"error,omitempty"`
}

func buscarClaveEnAPI(filename string, usuario string) (*ClaveResponse, error) {
	apiURL := "http://localhost:5000/api/buscar-clave"

	data := map[string]string{
		"filename": filename,
		"usuario":  usuario,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error al codificar JSON: %v", err)
	}

	resp, err := http.Post(apiURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("error al conectar con Flask: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error al leer respuesta: %v", err)
	}

	var result ClaveResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("error al decodificar JSON: %v", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("error: %s", result.Error)
	}

	return &result, nil
}

func descifrarArchivoCBC(archivoEntrada, archivoSalida string, key []byte, iv []byte) error {
	encryptedData, err := ioutil.ReadFile(archivoEntrada)
	if err != nil {
		return fmt.Errorf("error al leer archivo: %v", err)
	}

	if len(encryptedData) < aes.BlockSize {
		return fmt.Errorf("archivo corrupto (%d bytes)", len(encryptedData))
	}

	if iv == nil || len(iv) == 0 {
		iv = encryptedData[:aes.BlockSize]
		encryptedData = encryptedData[aes.BlockSize:]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error al crear cipher: %v", err)
	}

	if len(iv) != aes.BlockSize {
		return fmt.Errorf("IV debe tener %d bytes, tiene %d", aes.BlockSize, len(iv))
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	if len(encryptedData)%aes.BlockSize != 0 {
		return fmt.Errorf("datos no alineados al bloque (%d bytes)", len(encryptedData)%aes.BlockSize)
	}

	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen <= 0 || paddingLen > aes.BlockSize {
		return fmt.Errorf("padding inválido (%d)", paddingLen)
	}

	for i := len(decrypted) - paddingLen; i < len(decrypted); i++ {
		if decrypted[i] != byte(paddingLen) {
			return fmt.Errorf("padding corrupto")
		}
	}

	decrypted = decrypted[:len(decrypted)-paddingLen]

	err = ioutil.WriteFile(archivoSalida, decrypted, 0644)
	if err != nil {
		return fmt.Errorf("error al guardar: %v", err)
	}

	fmt.Printf("✅ Archivo descifrado: %s (%d bytes)\n", archivoSalida, len(decrypted))
	return nil
}

func main() {
	fmt.Println("========================================")
	fmt.Println("🔓 GUARDIAN - Descifrador AES-256-CBC")
	fmt.Println("========================================")

	if len(os.Args) < 2 {
		fmt.Println("Uso: go run desc.go <archivo.bin> [archivo_salida] [usuario]")
		fmt.Println()
		fmt.Println("Ejemplo:")
		fmt.Println("  go run desc.go HOLA.txt.bin")
		fmt.Println("  go run desc.go HOLA.txt.bin resultado.pdf admin@guardian.com")
		os.Exit(1)
	}

	archivoEntrada := os.Args[1]
	archivoSalida := ""
	usuario := "anonimo"

	if len(os.Args) >= 3 {
		archivoSalida = os.Args[2]
	} else {
		baseName := archivoEntrada
		if strings.HasSuffix(baseName, ".bin") {
			baseName = baseName[:len(baseName)-4]
		}
		archivoSalida = baseName + "_descifrado.pdf"
	}

	if len(os.Args) >= 4 {
		usuario = os.Args[3]
	}

	fmt.Printf("📁 Entrada: %s\n", archivoEntrada)
	fmt.Printf("📄 Salida: %s\n", archivoSalida)
	fmt.Printf("👤 Usuario: %s\n", usuario)

	if _, err := os.Stat(archivoEntrada); os.IsNotExist(err) {
		fmt.Printf("❌ El archivo '%s' no existe\n", archivoEntrada)
		os.Exit(1)
	}

	fmt.Println("🔍 Buscando clave en MongoDB...")
	claveInfo, err := buscarClaveEnAPI(archivoEntrada, usuario)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		fmt.Println("💡 Asegúrate de que el servidor Flask esté corriendo")
		os.Exit(1)
	}

	key, err := base64.StdEncoding.DecodeString(claveInfo.ClaveBase64)
	if err != nil {
		fmt.Printf("❌ Error al decodificar clave: %v\n", err)
		os.Exit(1)
	}

	iv, err := base64.StdEncoding.DecodeString(claveInfo.IVBase64)
	if err != nil {
		fmt.Printf("❌ Error al decodificar IV: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Clave encontrada: %s\n", claveInfo.NombreOriginal)
	fmt.Printf("🔑 Clave: %d bytes\n", len(key))

	fmt.Println("🔄 Descifrando...")
	err = descifrarArchivoCBC(archivoEntrada, archivoSalida, key, iv)
	if err != nil {
		fmt.Printf("❌ Error al descifrar: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("========================================")
	fmt.Println("✅ Descifrado completado")
	fmt.Println("========================================")
}
