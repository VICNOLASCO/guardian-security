package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ArchivoCifradoInfo struct {
	NombreOriginal string `json:"nombre_original"`
	Fecha          string `json:"fecha"`
	ClaveBase64    string `json:"clave_base64"`
	IVBase64       string `json:"iv_base64"`
	Usuario        string `json:"usuario"`
}

func generarBytesAleatorios(length int) ([]byte, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func cifrarArchivoCBC(archivoEntrada, archivoSalida string, key []byte, iv []byte) error {
	textoPlano, err := ioutil.ReadFile(archivoEntrada)
	if err != nil {
		return fmt.Errorf("error al leer archivo: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error al crear cipher: %v", err)
	}

	if len(iv) != aes.BlockSize {
		return fmt.Errorf("el IV debe tener %d bytes, tiene %d", aes.BlockSize, len(iv))
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	paddingLen := aes.BlockSize - (len(textoPlano) % aes.BlockSize)
	if paddingLen == 0 {
		paddingLen = aes.BlockSize
	}
	paddedText := make([]byte, len(textoPlano)+paddingLen)
	copy(paddedText, textoPlano)
	for i := len(textoPlano); i < len(paddedText); i++ {
		paddedText[i] = byte(paddingLen)
	}

	encrypted := make([]byte, len(paddedText))
	mode.CryptBlocks(encrypted, paddedText)

	finalData := append(iv, encrypted...)

	err = ioutil.WriteFile(archivoSalida, finalData, 0644)
	if err != nil {
		return fmt.Errorf("error al guardar archivo: %v", err)
	}

	fmt.Printf("✅ Archivo cifrado: %s (%d bytes)\n", archivoSalida, len(finalData))
	return nil
}

func guardarClaveEnMongoDB(info ArchivoCifradoInfo) error {
	data := map[string]interface{}{
		"nombre_original": info.NombreOriginal,
		"clave_base64":    info.ClaveBase64,
		"iv_base64":       info.IVBase64,
		"usuario":         info.Usuario,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := http.Post(
		"http://localhost:5000/api/guardar-clave",
		"application/json",
		strings.NewReader(string(jsonData)),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("error al guardar en MongoDB: %s", resp.Status)
	}

	fmt.Println("✅ Clave guardada en MongoDB")
	return nil
}

func guardarInfoLocal(info ArchivoCifradoInfo, nombreArchivo string) error {
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}

	baseName := strings.TrimSuffix(nombreArchivo, ".bin")
	jsonFile := baseName + ".json"
	err = ioutil.WriteFile(jsonFile, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("📝 Información guardada en: %s\n", jsonFile)
	return nil
}

func manejarCifrado(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("archivo")
	if err != nil {
		http.Error(w, "Error al recibir archivo", http.StatusBadRequest)
		return
	}
	defer file.Close()

	usuario := r.FormValue("usuario")
	if usuario == "" {
		usuario = "anonimo"
	}

	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Error al leer archivo", http.StatusInternalServerError)
		return
	}

	key, err := generarBytesAleatorios(32)
	if err != nil {
		http.Error(w, "Error al generar clave", http.StatusInternalServerError)
		return
	}

	iv, err := generarBytesAleatorios(16)
	if err != nil {
		http.Error(w, "Error al generar IV", http.StatusInternalServerError)
		return
	}

	tempFile, err := ioutil.TempFile("", "guardian_*")
	if err != nil {
		http.Error(w, "Error al crear temporal", http.StatusInternalServerError)
		return
	}
	tempPath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tempPath)

	err = ioutil.WriteFile(tempPath, fileContent, 0644)
	if err != nil {
		http.Error(w, "Error al escribir temporal", http.StatusInternalServerError)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	nombreSalida := fmt.Sprintf("Encriptado_%s.bin", timestamp)

	err = cifrarArchivoCBC(tempPath, nombreSalida, key, iv)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error al cifrar: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(nombreSalida)

	info := ArchivoCifradoInfo{
		NombreOriginal: handler.Filename,
		Fecha:          time.Now().Format("2006-01-02 15:04:05"),
		ClaveBase64:    base64.StdEncoding.EncodeToString(key),
		IVBase64:       base64.StdEncoding.EncodeToString(iv),
		Usuario:        usuario,
	}

	err = guardarClaveEnMongoDB(info)
	if err != nil {
		fmt.Printf("⚠️ Error en MongoDB: %v\n", err)
		guardarInfoLocal(info, nombreSalida)
	} else {
		guardarInfoLocal(info, nombreSalida)
	}

	cifradoData, err := ioutil.ReadFile(nombreSalida)
	if err != nil {
		http.Error(w, "Error al leer cifrado", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", nombreSalida))
	w.Write(cifradoData)

	fmt.Printf("✅ Cifrado: %s → %s (usuario: %s)\n", handler.Filename, nombreSalida, usuario)
}

func servirIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index1.html")
}

func main() {
	fmt.Println("========================================")
	fmt.Println("🔒 GUARDIAN - Cifrador AES-256-CBC")
	fmt.Println("========================================")

	http.HandleFunc("/", servirIndex)
	http.HandleFunc("/encriptar", manejarCifrado)

	puerto := ":8080"
	fmt.Printf("🚀 Servidor en http://localhost%s\n", puerto)
	fmt.Println("✅ Las claves se guardan en MongoDB")
	fmt.Println("========================================")

	err := http.ListenAndServe(puerto, nil)
	if err != nil {
		log.Fatalf("❌ Error: %v", err)
	}
}
