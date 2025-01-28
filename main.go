package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketData represents the structure of the JSON data
type PacketData struct {
	Interface       string    `json:"interface"`
	Timestamp       time.Time `json:"timestamp"`
	Size            int       `json:"size"`
	Protocol        string    `json:"protocol"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	SourcePort      uint16    `json:"source_port"`
	DestinationPort uint16    `json:"destination_port"`
	PacketType      string    `json:"packet_type"`
	Flags           []string  `json:"flags"`
}

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Available devices:")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("   Description: %s\n", device.Description)
		}
		for _, address := range device.Addresses {
			fmt.Printf("   IP address: %s\n", address.IP)
			fmt.Printf("   Subnet mask: %s\n", address.Netmask)
		}
		fmt.Println()
	}

	// Get user selection
	fmt.Print("Enter the number of the interface you want to capture (1-", len(devices), "): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	var selectedIndex int
	_, err = fmt.Sscanf(strings.TrimSpace(input), "%d", &selectedIndex)
	if err != nil || selectedIndex < 1 || selectedIndex > len(devices) {
		log.Fatal("Invalid interface selection")
	}

	deviceName := devices[selectedIndex-1].Name
	fmt.Printf("Selected device: %s\n", deviceName)

	// Open device
	handle, err := pcap.OpenLive(deviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter for TCP and UDP traffic only
	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	var packets []PacketData

	fmt.Printf("Starting packet capture on %s...\n", deviceName)
	fmt.Println("Press Ctrl+C to stop capturing")

	// Create output directory if it doesn't exist
	if err := os.MkdirAll("captured_packets", 0755); err != nil {
		log.Fatal("Error creating output directory:", err)
	}

	startTime := time.Now()
	lastStatusTime := startTime

	for packet := range packetSource.Packets() {
		packetCount++

		packetInfo := PacketData{
			Interface: deviceName,
			Timestamp: packet.Metadata().Timestamp,
			Size:      packet.Metadata().Length,
		}

		// Extract IP layer
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, ok := ipLayer.(*layers.IPv4)
			if ok {
				packetInfo.SourceIP = ip.SrcIP.String()
				packetInfo.DestinationIP = ip.DstIP.String()
				packetInfo.PacketType = "IPv4"
			}
		}

		// Extract TCP layer
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if ok {
				packetInfo.Protocol = "TCP"
				packetInfo.SourcePort = uint16(tcp.SrcPort)
				packetInfo.DestinationPort = uint16(tcp.DstPort)
				packetInfo.Flags = getTCPFlags(tcp)
			}
		}

		// Extract UDP layer
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if ok {
				packetInfo.Protocol = "UDP"
				packetInfo.SourcePort = uint16(udp.SrcPort)
				packetInfo.DestinationPort = uint16(udp.DstPort)
			}
		}

		// Print real-time packet info
		fmt.Printf("\rPackets captured: %d | Last packet: %s:%d → %s:%d (%s)",
			packetCount,
			packetInfo.SourceIP,
			packetInfo.SourcePort,
			packetInfo.DestinationIP,
			packetInfo.DestinationPort,
			packetInfo.Protocol)

		packets = append(packets, packetInfo)

		// Write to JSON every 100 packets or if 30 seconds have passed
		currentTime := time.Now()
		if packetCount%100 == 0 || currentTime.Sub(lastStatusTime) >= 30*time.Second {
			writeToJSON(packets, packetCount)
			packets = nil // Reset the packet list
			lastStatusTime = currentTime

			// Print statistics
			duration := currentTime.Sub(startTime)
			packetsPerSecond := float64(packetCount) / duration.Seconds()
			fmt.Printf("\n\nStatistics after %v:\n", duration.Round(time.Second))
			fmt.Printf("Total packets: %d\n", packetCount)
			fmt.Printf("Average packets/second: %.2f\n\n", packetsPerSecond)
		}
	}
}

func getTCPFlags(tcp *layers.TCP) []string {
	var flags []string
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return flags
}

func writeToJSON(packets []PacketData, packetCount int) {
	if len(packets) == 0 {
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("captured_packets/packets_%d_%s.json", packetCount, timestamp)

	file, err := os.Create(fileName)
	if err != nil {
		log.Printf("Error creating file %s: %v", fileName, err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(packets); err != nil {
		log.Printf("Error encoding JSON to %s: %v", fileName, err)
		return
	}

	fmt.Printf("\nWritten %d packets to %s\n", len(packets), fileName)
}
