package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
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

	result := make([]net.IP, 0)
	var wg sync.WaitGroup
	wg.Add(len(ips))
	for _, addr := range ips {
		addr := addr
		go func() {
			defer wg.Done()
			found := Ping(addr, time.Second)
			if !found {
				return
			}
			_, err := GetRPiMACAddress(addr)
			if err != nil {
				return
			}
			result = append(result, addr)
		}()
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	for _, a := range result {
		fmt.Println(a)
	}
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

func Ping(target net.IP, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-W", fmt.Sprint(timeout.Seconds()), "-c", "1", target.String())
	err := cmd.Run()
	return err == nil
}
func GetRPiMACAddress(ip net.IP) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "arp", ip.String())
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v, err: %w", string(b), err)
	}
	r := regexp.MustCompile("b8:27:eb:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}")
	s := string(b)
	mac := r.FindString(s)
	if mac == "" {
		return "", fmt.Errorf("%v(%v) is not Raspberry Pi's address", s, ip)
	}

	return mac, nil
}

func AllIPAddrInNetwork(ipArr, maskArr [4]byte) []net.IP {
	ip := ToInt32(ipArr)
	mask := ToInt32(maskArr)
	networkAddr := ip & mask
	lastAddress := ip | ^mask
	result := make([]net.IP, 0, lastAddress-networkAddr)
	for addr := networkAddr + 1; addr < lastAddress; addr++ {
		if addr == ip {
			continue
		}
		s := ToArr(addr)
		result = append(result, net.IPv4(s[0], s[1], s[2], s[3]))
	}
	return result
}

func ToInt32(arr [4]byte) int32 {
	var result int32 = 0
	for i := 0; i < 4; i++ {
		result += int32(arr[i]) << (8 * (3 - i))
	}
	return result
}

func ToArr(addr int32) [4]byte {
	var result [4]byte
	for i := 0; i < 4; i++ {
		result[i] = byte((addr >> ((3 - i) * 8)) & 255)
	}
	return result
}
