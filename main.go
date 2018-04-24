package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"fmt"
	"github.com/google/gopacket/layers"
	"time"
)

var (
	pcapFile string = "test.pcap"
	handle   *pcap.Handle
	err      error
)

func openPcap(file string) *pcap.Handle {
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil { log.Fatal(err) }
	return handle
}

func main() {
	if len(os.Args) == 2 {
		pcapFile = os.Args[1]
	}

	fmt.Println("Checking file: " + pcapFile)

	handle := openPcap(pcapFile)
	defer handle.Close()

	var filter string = "dst host 192.168.1.45"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//var prevTime time.Time
	//var times []time.Duration

	trafficPresent := false
	for packet := range packetSource.Packets() {

		ip4 := packet.Layer(layers.LayerTypeIPv4)
		if ip4 != nil {
			if packet.NetworkLayer().NetworkFlow().Src().String() == "192.168.1.36" {
				if packet.NetworkLayer().NetworkFlow().Dst().String() == "192.168.1.45" {
					if len(packet.Data()) == 74 {
						trafficPresent = true
					}
				}
			}
		}
	}

	time.Sleep(5 * time.Second)

	if trafficPresent {
		fmt.Println("Hidden data is present in file.")
	} else {
		fmt.Println("There is no hidden data in this file.")
	}



}
