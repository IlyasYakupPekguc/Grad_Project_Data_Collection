package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type PacketData struct {
	Interface       string    `json:"interface"`
	Timestamp       time.Time `json:"timestamp"`
	Size            int       `json:"size"`
	Protocol        string    `json:"protocol"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	SourcePort      int       `json:"source_port,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	TTL             int       `json:"ttl,omitempty"`
	TCPFlags        string    `json:"tcp_flags,omitempty"`
	PacketType      string    `json:"packet_type"`
	Direction       string    `json:"direction"`
	PayloadHash     string    `json:"payload_hash,omitempty"`
	Hour            int       `json:"hour"`
	Minute          int       `json:"minute"`
	Second          int       `json:"second"`
	DayOfWeek       string    `json:"day_of_week"`
}

type NetworkData struct {
	StartTime   time.Time    `json:"start_time"`
	EndTime     time.Time    `json:"end_time"`
	PacketCount int          `json:"packet_count"`
	Packets     []PacketData `json:"packets"`
}

func saveToJSON(data NetworkData, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(data)
}

func capturePackets(deviceName string, wg *sync.WaitGroup, dataChan chan<- PacketData) {
	defer wg.Done()

	handle, err := pcap.OpenLive(
		deviceName,
		1600,
		true,
		30*time.Second,
	)
	if err != nil {
		log.Printf("Error opening device %s: %v", deviceName, err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		log.Printf("Error setting BPF filter on %s: %v", deviceName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("Started capturing on interface: %s\n", deviceName)

	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp

		packetData := PacketData{
			Interface: deviceName,
			Timestamp: timestamp,
			Size:      len(packet.Data()),
			Hour:      timestamp.Hour(),
			Minute:    timestamp.Minute(),
			Second:    timestamp.Second(),
			DayOfWeek: timestamp.Weekday().String(),
		}

		if netLayer := packet.NetworkLayer(); netLayer != nil {
			packetData.PacketType = netLayer.LayerType().String()

			// Sadece IPv4 paketlerini işle
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				ipv4, _ := ipv4Layer.(*layers.IPv4)
				packetData.SourceIP = ipv4.SrcIP.String()
				packetData.DestinationIP = ipv4.DstIP.String()

				// Paket yakalandığında buraya kadar geldiyse bir IPv4 paketidir
				if transportLayer := packet.TransportLayer(); transportLayer != nil {
					packetData.Protocol = transportLayer.LayerType().String()
					if tcp, ok := transportLayer.(*layers.TCP); ok {
						packetData.SourcePort = int(tcp.SrcPort)
						packetData.DestinationPort = int(tcp.DstPort)
						packetData.TTL = int(tcp.Window)
						packetData.TCPFlags = fmt.Sprintf("SYN=%v ACK=%v FIN=%v", tcp.SYN, tcp.ACK, tcp.FIN)
					}
					if udp, ok := transportLayer.(*layers.UDP); ok {
						packetData.SourcePort = int(udp.SrcPort)
						packetData.DestinationPort = int(udp.DstPort)
					}

					// Paketi kanala gönder
					dataChan <- packetData

					// Debug çıktısı
					fmt.Printf("\nPacket on %s:\n", deviceName)
					fmt.Printf("Time: %v\n", timestamp.Format("15:04:05"))
					fmt.Printf("Size: %d bytes\n", len(packet.Data()))
					fmt.Printf("Protocol: %s\n", packetData.Protocol)
					fmt.Printf("Source: %s:%d\n", packetData.SourceIP, packetData.SourcePort)
					fmt.Printf("Destination: %s:%d\n", packetData.DestinationIP, packetData.DestinationPort)
				}
			}
		}
	}
}

func processPackets(dataChan chan PacketData, done chan bool) {
	// İlk JSON dosyasını oluştur
	fileCounter := 1
	currentData := NetworkData{
		StartTime: time.Now(),
		Packets:   make([]PacketData, 0),
	}

	filename := fmt.Sprintf("network_data_%d_%s.json",
		fileCounter,
		currentData.StartTime.Format("2006-01-02_15-04-05"))
	fmt.Printf("Created new JSON file: %s\n", filename)

	for packet := range dataChan {
		// Paketi mevcut veriye ekle
		currentData.Packets = append(currentData.Packets, packet)
		currentData.PacketCount++

		// Her 100 pakette bir dosyaya kaydet (debug için)
		if currentData.PacketCount%100 == 0 {
			fmt.Printf("\rCurrent packet count: %d in file %d", currentData.PacketCount, fileCounter)
		}

		// 100,000 pakete ulaşıldığında
		if currentData.PacketCount >= 10000 {
			// Mevcut dosyayı kaydet
			currentData.EndTime = time.Now()
			if err := saveToJSON(currentData, filename); err != nil {
				log.Printf("Error saving JSON %d: %v", fileCounter, err)
			} else {
				fmt.Printf("\nData saved to %s (%d packets)\n", filename, currentData.PacketCount)
			}

			// Yeni dosya için hazırlık
			fileCounter++
			currentData = NetworkData{
				StartTime: time.Now(),
				Packets:   make([]PacketData, 0),
			}
			filename = fmt.Sprintf("network_data_%d_%s.json",
				fileCounter,
				currentData.StartTime.Format("2006-01-02_15-04-05"))
			fmt.Printf("Created new JSON file: %s\n", filename)
		}
	}

	// Son dosyayı kaydet
	if currentData.PacketCount > 0 {
		currentData.EndTime = time.Now()
		if err := saveToJSON(currentData, filename); err != nil {
			log.Printf("Error saving final JSON: %v", err)
		} else {
			fmt.Printf("\nFinal data saved to %s (%d packets)\n", filename, currentData.PacketCount)
		}
	}

	done <- true
}

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding devices:", err)
	}

	if len(devices) == 0 {
		log.Fatal("No network interfaces found")
	}

	fmt.Println("Available interfaces:")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		fmt.Printf("   Description: %s\n", device.Description)
		for _, address := range device.Addresses {
			fmt.Printf("   IP: %s\n", address.IP)
		}
		fmt.Println("----------------------------------------")
	}

	var wg sync.WaitGroup
	dataChan := make(chan PacketData, 1000)

	for _, device := range devices {
		wg.Add(1)
		go capturePackets(device.Name, &wg, dataChan)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("\nStarted capturing packets. Press Ctrl+C to stop and save...")

	done := make(chan bool)
	go processPackets(dataChan, done)

	<-sigChan

	fmt.Println("\nStopping capture...")
	close(dataChan)
	<-done

	wg.Wait()
}
