package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	ip, err := GetOutboundIP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get outbound IP address: %v\n", err)
		os.Exit(1)
	}

	ip = ip.To4()
	if ip == nil {
		fmt.Fprintf(os.Stderr, "IPv6 is not supported.\n")
		os.Exit(1)
	}

	mask := ip.DefaultMask()

	var ipArr [4]byte
	copy(ipArr[:], ip)
	var maskArr [4]byte
	copy(maskArr[:], mask)

	ips := AllIPAddrInNetwork(ipArr, maskArr)

	limit := make(chan struct{}, 100)
	var wg sync.WaitGroup
	wg.Add(len(ips))
	for _, addr := range ips {
		limit <- struct{}{}
		go func(addr net.IP) {
			defer wg.Done()
			defer func() { <-limit }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:80", addr), time.Millisecond*300)
			if err != nil {
				return
			}
			conn.Close()
		}(addr)
	}
	wg.Wait()
	result, err := GetRPiMacAddress(net.IPNet{IP: ip, Mask: mask})
	if err != nil {
		panic(err)
	}

	for _, a := range result {
		fmt.Println(a)
	}
}

func GetRPiMacAddress(ipNet net.IPNet) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	cmd := exec.CommandContext(ctx, "arp", "-a")
	b, err := cmd.CombinedOutput()
	s := string(b)
	if err != nil {
		return nil, fmt.Errorf("arp failed. output: %v, err: %w", s, err)
	}
	r := regexp.MustCompile("\\(([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\) at b8:27:eb:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}")

	matches := r.FindAllStringSubmatch(s, -1)
	result := make([]net.IP, 0)
	for _, match := range matches {
		ip := IPFromString(match[1])
		if !ipNet.Contains(ip) {
			continue
		}
		result = append(result, ip)
	}

	return result, nil
}

func IPFromString(s string) net.IP {
	strs := strings.Split(s, ".")
	nums := make([]byte, len(strs))
	for i, s := range strs {
		n, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			panic(err)
		}
		nums[i] = byte(n)
	}
	return net.IPv4(nums[0], nums[1], nums[2], nums[3])
}

func GetOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

func AllIPAddrInNetwork(ipArr, maskArr [4]byte) []net.IP {
	ip := binary.BigEndian.Uint32(ipArr[:])
	mask := binary.BigEndian.Uint32(maskArr[:])
	networkAddr := ip & mask
	lastAddress := ip | ^mask
	result := make([]net.IP, 0, lastAddress-networkAddr)
	for addr := networkAddr + 1; addr < lastAddress; addr++ {
		if addr == ip {
			continue
		}
		var s [4]byte
		binary.BigEndian.PutUint32(s[:], addr)
		result = append(result, net.IPv4(s[0], s[1], s[2], s[3]))
	}
	return result
}
