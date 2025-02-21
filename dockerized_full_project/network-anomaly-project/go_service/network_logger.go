package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type NetworkData struct {
	Timestamp      string `json:"timestamp"`
	Length         int    `json:"length"`
	SourceIP       string `json:"source_ip"`
	DestinationIP  string `json:"destination_ip"`
	SourcePort     string `json:"source_port"`
	DestinationPort string `json:"destination_port"`
	Protocol       string `json:"protocol"`
}

func main() {
	dataDir := "./data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		os.Mkdir(dataDir, os.ModePerm)
	}

	for {
		// Fake JSON veri oluştur
		networkData := []NetworkData{
			{
				Timestamp:      time.Now().Format(time.RFC3339),
				Length:         1024,
				SourceIP:       "192.168.1.1",
				DestinationIP:  "192.168.1.100",
				SourcePort:     "443",
				DestinationPort: "50000",
				Protocol:       "TCP",
			},
		}

		// JSON dosyası oluştur
		filename := fmt.Sprintf("%s/data_%d.json", dataDir, time.Now().Unix())
		file, _ := os.Create(filename)
		defer file.Close()

		json.NewEncoder(file).Encode(networkData)
		fmt.Println("Saved:", filename)

		time.Sleep(10 * time.Second) // 10 saniyede bir veri oluştur
	}
}
