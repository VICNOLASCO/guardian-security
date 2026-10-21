package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
)

// Estructura para respuesta JSON
type Response struct {
    Success      bool   `json:"success"`
    Message      string `json:"message"`
    OutputFile   string `json:"output_file"`
    OriginalName string `json:"original_name"`
    MimeType     string `json:"mime_type"`
}

// Magic numbers para detección de tipo de archivo
func detectFileType(data []byte) string {
    if len(data) < 4 {
        return "bin"
    }

    // PDF
    if string(data[:4]) == "%PDF" {
        return "pdf"
    }
    // ZIP / DOCX / XLSX / PPTX
    if len(data) >= 2 && string(data[:2]) == "PK" {
        if len(data) > 100 {
            content := string(data[:100])
            if strings.Contains(content, "word/") {
                return "docx"
            }
            if strings.Contains(content, "xl/") {
                return "xlsx"
            }
            if strings.Contains(content, "ppt/") {
                return "pptx"
            }
        }
        return "zip"
    }
    // JPG
    if len(data) >= 2 && string(data[:2]) == "\xff\xd8" {
        return "jpg"
    }
    // PNG
    if len(data) >= 8 && string(data[:8]) == "\x89PNG\r\n\x1a\n" {
        return "png"
    }
    // GIF
    if len(data) >= 6 && (string(data[:6]) == "GIF89a" || string(data[:6]) == "GIF87a") {
        return "gif"
    }
    // BMP
    if len(data) >= 2 && string(data[:2]) == "BM" {
        return "bmp"
    }
    // MP3
    if len(data) >= 2 && string(data[:2]) == "\xff\xfb" {
        return "mp3"
    }
    // MP4
    if len(data) >= 12 && string(data[4:12]) == "ftypmp4" {
        return "mp4"
    }
    // JSON
    if len(data) >= 1 && (string(data[:1]) == "{" || string(data[:1]) == "[") {
        return "json"
    }
    // XML
    if len(data) >= 5 && string(data[:5]) == "<?xml" {
        return "xml"
    }
    // HTML
    if len(data) >= 6 && (string(data[:6]) == "<html" || string(data[:6]) == "<!DOCT") {
        return "html"
    }
    // TXT - intentar decodificar UTF-8
    if isUTF8(data) {
        return "txt"
    }

    return "bin"
}

func isUTF8(data []byte) bool {
    try := string(data)
    for _, r := range try {
        if r == 0xFFFD {
            return false
        }
    }
    return true
}

func getMimeType(ext string) string {
    mimeTypes := map[string]string{
        "pdf":  "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "jpg":  "image/jpeg",
        "jpeg": "image/jpeg",
        "png":  "image/png",
        "gif":  "image/gif",
        "bmp":  "image/bmp",
        "txt":  "text/plain",
        "json": "application/json",
        "xml":  "application/xml",
        "html": "text/html",
        "zip":  "application/zip",
        "mp3":  "audio/mpeg",
        "mp4":  "video/mp4",
        "bin":  "application/octet-stream",
    }
    ext = strings.ToLower(strings.TrimPrefix(ext, "."))
    if val, ok := mimeTypes[ext]; ok {
        return val
    }
    return "application/octet-stream"
}

func decryptFile(inputPath, outputDir, keyBase64, ivBase64, tagBase64, originalName string) (string, string, error) {
    // Decodificar clave, IV y TAG
    key, err := base64.StdEncoding.DecodeString(keyBase64)
    if err != nil {
        return "", "", fmt.Errorf("error decodificando clave: %v", err)
    }

    nonce, err := base64.StdEncoding.DecodeString(ivBase64)
    if err != nil {
        return "", "", fmt.Errorf("error decodificando IV: %v", err)
    }

    tag, err := base64.StdEncoding.DecodeString(tagBase64)
    if err != nil {
        return "", "", fmt.Errorf("error decodificando TAG: %v", err)
    }

    // Leer archivo cifrado
    encryptedData, err := ioutil.ReadFile(inputPath)
    if err != nil {
        return "", "", fmt.Errorf("error leyendo archivo: %v", err)
    }

    // Verificar tamaño mínimo (IV 12 + algo de datos)
    if len(encryptedData) < 12 {
        return "", "", fmt.Errorf("archivo corrupto: tamaño mínimo no alcanzado")
    }

    // Extraer IV del archivo (los primeros 12 bytes)
    actualNonce := encryptedData[:12]
    ciphertextWithTag := encryptedData[12:]

    // Crear cipher AES-GCM
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", "", fmt.Errorf("error creando cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", "", fmt.Errorf("error creando GCM: %v", err)
    }

    // Descifrar con verificación de autenticación
    plaintext, err := gcm.Open(nil, actualNonce, ciphertextWithTag, nil)
    if err != nil {
        return "", "", fmt.Errorf("error de autenticación: el archivo puede estar corrupto o modificado")
    }

    // Detectar tipo de archivo
    fileType := detectFileType(plaintext)

    // Determinar extensión final
    ext := ""
    if originalName != "" && strings.Contains(originalName, ".") {
        parts := strings.Split(originalName, ".")
        if len(parts) > 1 {
            ext = strings.ToLower(parts[len(parts)-1])
        }
    }

    // Si la extensión detectada es más confiable, usarla
    if fileType != "bin" && fileType != ext {
        ext = fileType
    }

    // Construir nombre de salida
    nameWithoutExt := originalName
    if strings.Contains(originalName, ".") {
        nameWithoutExt = strings.Split(originalName, ".")[0]
    }
    if nameWithoutExt == "" {
        nameWithoutExt = "archivo_descifrado"
    }

    outputName := nameWithoutExt
    if ext != "" {
        outputName = nameWithoutExt + "." + ext
    }

    outputPath := filepath.Join(outputDir, outputName)

    // Guardar archivo descifrado
    if err := ioutil.WriteFile(outputPath, plaintext, 0644); err != nil {
        return "", "", fmt.Errorf("error escribiendo archivo: %v", err)
    }

    mimeType := getMimeType(ext)

    return outputName, mimeType, nil
}

func main() {
    if len(os.Args) < 7 {
        response := Response{
            Success: false,
            Message: "Uso: decryptor <input_file> <output_dir> <key_base64> <iv_base64> <tag_base64> <original_name>",
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    inputFile := os.Args[1]
    outputDir := os.Args[2]
    keyBase64 := os.Args[3]
    ivBase64 := os.Args[4]
    tagBase64 := os.Args[5]
    originalName := os.Args[6]

    // Verificar archivo
    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        response := Response{
            Success: false,
            Message: fmt.Sprintf("Archivo no encontrado: %s", inputFile),
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    // Descifrar
    outputFile, mimeType, err := decryptFile(inputFile, outputDir, keyBase64, ivBase64, tagBase64, originalName)
    if err != nil {
        response := Response{
            Success: false,
            Message: fmt.Sprintf("Error descifrando: %v", err),
        }
        json.NewEncoder(os.Stdout).Encode(response)
        os.Exit(1)
    }

    response := Response{
        Success:      true,
        Message:      "Archivo descifrado correctamente con AES-256-GCM",
        OutputFile:   outputFile,
        OriginalName: originalName,
        MimeType:     mimeType,
    }

    json.NewEncoder(os.Stdout).Encode(response)
}
