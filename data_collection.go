package main

import (
	"crypto/sha256"
	"encoding/hex"
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

// PacketData tekil paket bilgilerini tutar
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

// NetworkData tüm ağ verilerini tutar
type NetworkData struct {
	StartTime   time.Time    `json:"start_time"`
	EndTime     time.Time    `json:"end_time"`
	PacketCount int          `json:"packet_count"`
	Packets     []PacketData `json:"packets"`
}

// saveToJSON verileri JSON dosyasına kaydeder
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

// capturePackets belirtilen interface üzerinden paket yakalar
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

		// Varsayılan PacketData
		packetData := PacketData{
			Interface: deviceName,
			Timestamp: timestamp,
			Size:      len(packet.Data()),
			Hour:      timestamp.Hour(),
			Minute:    timestamp.Minute(),
			Second:    timestamp.Second(),
			DayOfWeek: timestamp.Weekday().String(),
		}

		// Packet tiplerini kontrol et
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			packetData.PacketType = netLayer.LayerType().String()
			packetData.SourceIP = netLayer.NetworkFlow().Src().String()
			packetData.DestinationIP = netLayer.NetworkFlow().Dst().String()
		}

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
		}

		// Payload Hash
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			hash := sha256.Sum256(appLayer.Payload())
			packetData.PayloadHash = hex.EncodeToString(hash[:])
		}

		dataChan <- packetData

		// Ekrana bilgi yazdır
		fmt.Printf("\nPacket on %s:\n", deviceName)
		fmt.Printf("Time: %v\n", timestamp.Format("15:04:05"))
		fmt.Printf("Size: %d bytes\n", len(packet.Data()))
		fmt.Printf("Protocol: %s\n", packetData.Protocol)
		fmt.Printf("Source: %s:%d\n", packetData.SourceIP, packetData.SourcePort)
		fmt.Printf("Destination: %s:%d\n", packetData.DestinationIP, packetData.DestinationPort)
	}
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

	// NetworkData yapısını oluştur
	networkData := NetworkData{
		StartTime: time.Now(),
		Packets:   make([]PacketData, 0),
	}

	// Her interface için goroutine başlat
	for _, device := range devices {
		wg.Add(1)
		go capturePackets(device.Name, &wg, dataChan)
	}

	// Graceful shutdown için sinyal yakalayıcı
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("\nStarted capturing packets. Press Ctrl+C to stop and save...")

	// Ana döngü
	go func() {
		for packet := range dataChan {
			networkData.Packets = append(networkData.Packets, packet)
			networkData.PacketCount++
		}
	}()

	// Programın kapanmasını bekle
	<-sigChan

	// Kapanış işlemleri
	fmt.Println("\nSaving data and shutting down...")
	close(dataChan)
	networkData.EndTime = time.Now()

	// JSON dosyasına kaydet
	filename := fmt.Sprintf("network_data_%s.json",
		time.Now().Format("2006-01-02_15-04-05"))

	if err := saveToJSON(networkData, filename); err != nil {
		log.Printf("Error saving JSON: %v", err)
	} else {
		fmt.Printf("Data saved to %s\n", filename)
	}

	wg.Wait()
}
