package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"
    "time"
)

// Estructura para respuesta JSON
type Response struct {
    Success      bool   `json:"success"`
    Message      string `json:"message"`
    OutputFile   string `json:"output_file"`
    KeyBase64    string `json:"key_base64"`
    IVBase64     string `json:"iv_base64"`
    TagBase64    string `json:"tag_base64"`
    OriginalName string `json:"original_name"`
}

func generateKey() ([]byte, error) {
    key := make([]byte, 32) // 256 bits
    _, err := rand.Read(key)
    if err != nil {
        return nil, err
    }
    return key, nil
}

func generateUID() string {
    b := make([]byte, 4)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}

func encryptFile(inputPath, outputPath string, key []byte) (string, string, string, error) {
    // Leer archivo
    plaintext, err := ioutil.ReadFile(inputPath)
    if err != nil {
        return "", "", "", fmt.Errorf("error leyendo archivo: %v", err)
    }

    // Crear cipher AES-GCM
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", "", "", fmt.Errorf("error creando cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", "", "", fmt.Errorf("error creando GCM: %v", err)
    }

    // Generar IV (nonce) de 12 bytes para GCM
    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", "", "", fmt.Errorf("error generando nonce: %v", err)
    }

    // Cifrar con GCM (autenticación integrada)
    // El tag de autenticación viene al final del ciphertext
    ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

    // Guardar: IV (12) + DATOS_CIFRADOS (incluye tag de 16 bytes al final)
    output := append(nonce, ciphertext...)

    if err := ioutil.WriteFile(outputPath, output, 0644); err != nil {
        return "", "", "", fmt.Errorf("error escribiendo archivo: %v", err)
    }

    // Extraer IV, Tag y datos para almacenar en MongoDB
    // ciphertext = datos_cifrados + tag (16 bytes)
    tagStart := len(ciphertext) - 16
    data := ciphertext[:tagStart]
    tag := ciphertext[tagStart:]

    return base64.StdEncoding.EncodeToString(nonce),
        base64.StdEncoding.EncodeToString(tag),
        base64.StdEncoding.EncodeToString(key),
        nil
}

func main() {
    if len(os.Args) < 3 {
        response := Response{
            Success: false,
            Message: "Uso: encryptor <input_file> <output_dir> [original_name]",
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    inputFile := os.Args[1]
    outputDir := os.Args[2]
    originalName := filepath.Base(inputFile)
    if len(os.Args) > 3 {
        originalName = os.Args[3]
    }

    // Verificar que el archivo existe
    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        response := Response{
            Success: false,
            Message: fmt.Sprintf("Archivo no encontrado: %s", inputFile),
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    // Generar clave única
    key, err := generateKey()
    if err != nil {
        response := Response{
            Success: false,
            Message: fmt.Sprintf("Error generando clave: %v", err),
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    // Generar nombre de salida
    timestamp := time.Now().Format("20060102_150405")
    uid := generateUID()
    outputName := fmt.Sprintf("Encriptado_%s_%s.bin", timestamp, uid)
    outputPath := filepath.Join(outputDir, outputName)

    // Cifrar
    ivBase64, tagBase64, keyBase64, err := encryptFile(inputFile, outputPath, key)
    if err != nil {
        response := Response{
            Success: false,
            Message: fmt.Sprintf("Error cifrando: %v", err),
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    // Responder con éxito
    response := Response{
        Success:      true,
        Message:      "Archivo cifrado correctamente con AES-256-GCM",
        OutputFile:   outputName,
        KeyBase64:    keyBase64,
        IVBase64:     ivBase64,
        TagBase64:    tagBase64,
        OriginalName: originalName,
    }

    json.NewEncoder(os.Stdout).Encode(response)
}
