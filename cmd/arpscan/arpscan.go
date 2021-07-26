// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// arpscan implements ARP scanning of all interfaces' local networks using
// gopacket and its subpackages.  This example shows, among other things:
//   * Generating and sending packet data
//   * Reading in packet data and interpreting it
//   * Use of the 'pcap' subpackage for reading/writing
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	r := flag.Bool("r", false, "show Raspberry Pi device")
	wait := flag.Uint("w", 1000, "wait milliseconds for packets")
	flag.Parse()

	// arpscan shows results only with MAC addresses which contains `filter`.
	filter := ""
	if *r {
		filter = "b8:27:eb" // Raspberry Pi specific address
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface, filter, *wait); err != nil {
				fmt.Fprintf(os.Stderr, "interface %v: %v\n", iface.Name, err)
			}
		}(iface)
	}
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface, filter string, wait uint) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		addr = getIPNet(a)
		if addr != nil {
			break
		}
	}

	// Sanity-check that the interface has a good address.
	if addr == nil {
		return nil
	} else if addr.IP[0] == 127 {
		return nil
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	results := make(chan *layers.ARP, 10)
	go readARP(handle, iface, stop, results)
	defer close(stop)
	// Write our scan packets out to the handle.
	if err := writeARP(handle, iface, addr); err != nil {
		fmt.Fprintf(os.Stderr, "error writing packets on %v: %v\n", iface.Name, err)
		return err
	}

	var history []net.IP
	var wg sync.WaitGroup
L:
	for {
		select {
		case arp := <-results:
			ip := net.IP(arp.SourceProtAddress)
			if contains(history, ip) {
				continue
			}
			history = append(history, ip)

			mac := net.HardwareAddr(arp.SourceHwAddress)
			if !strings.Contains(mac.String(), filter) {
				continue
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				name, _ := LookupAddrForMDNS(ip)

				// Note:  we might get some packets here that aren't responses to ones we've sent,
				// if for example someone else sends US an ARP request.  Doesn't much matter, though...
				// all information is good information :)
				fmt.Printf("IP %v (%v) is at %v\n", ip, name, mac)
			}()
		case <-time.After(time.Millisecond * time.Duration(wait)):
			break L
		}
	}
	wg.Wait()

	return nil
}

func getIPNet(addr net.Addr) *net.IPNet {
	ipNet, ok := addr.(*net.IPNet)
	if !ok {
		return nil
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil
	}

	return &net.IPNet{
		IP:   ip4,
		Mask: ipNet.Mask[len(ipNet.Mask)-4:],
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}, results chan<- *layers.ARP) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal(iface.HardwareAddr, arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			results <- arp
		}
	}
}

func contains(ips []net.IP, target net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

func LookupAddrForMDNS(ip net.IP) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "-x", ip.String(), "@224.0.0.251", "-p", "5353")
	b, err := cmd.CombinedOutput()
	str := strings.TrimRight(string(b), ".\n")
	if err != nil {
		return "", fmt.Errorf("dig command failed: %w, stdout+stderr: %v", err, str)
	}
	return str, nil
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = ip
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32(n.IP)
	mask := binary.BigEndian.Uint32(n.Mask)
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}
