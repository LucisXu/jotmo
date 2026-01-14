// +build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func main() {
	// Login first
	loginBody := `{"username":"xuhuayan","password":"xuhuayan"}`
	resp, err := http.Post("http://localhost:8088/api/login", "application/json", bytes.NewBufferString(loginBody))
	if err != nil {
		fmt.Println("Login error:", err)
		return
	}
	defer resp.Body.Close()

	var loginResp struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&loginResp)
	fmt.Println("Token:", loginResp.Token[:30], "...")

	// Trigger recluster
	req, _ := http.NewRequest("POST", "http://localhost:8088/api/categories/recluster", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)

	client := &http.Client{}
	resp2, err := client.Do(req)
	if err != nil {
		fmt.Println("Recluster error:", err)
		return
	}
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)
	fmt.Println("Response:", string(body))
}
