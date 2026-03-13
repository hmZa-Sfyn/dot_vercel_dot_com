package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP     string
	Ports  []int
}

var (
	fetchURL   = "https://raw.githubusercontent.com/disposable/cloud-ip-ranges/master/txt/vercel.txt"
	defaultConcurrency = 200
	defaultTimeout     = 3 * time.Second
)

func main() {
	concurrency := flag.Int("concurrency", defaultConcurrency, "Max concurrent scans")
	timeoutSec := flag.Int("timeout", 3, "Dial timeout in seconds")
	allOwned := flag.Bool("all", false, "Also scan the two huge /16 blocks (slow!)")
	rangesFile := flag.String("file", "", "Custom CIDR file (one per line)")
	flag.Parse()

	// Get ranges
	var cidrs []string
	if *rangesFile != "" {
		cidrs = loadFile(*rangesFile)
	} else {
		cidrs = fetchVercelRanges(*allOwned)
	}

	fmt.Printf("🔍 Scanning %d Vercel IP ranges (%d total IPs approx)\n", len(cidrs), estimateIPs(cidrs))
	fmt.Println("Ports: 80 & 443 | Timeout:", *timeoutSec, "s | Concurrency:", *concurrency)

	results := scanAll(cidrs, *concurrency, time.Duration(*timeoutSec)*time.Second)
	printResults(results)
}

func fetchVercelRanges(includeLarge bool) []string {
	resp, err := http.Get(fetchURL)
	if err != nil {
		fmt.Println("⚠️ Failed to fetch latest ranges, using built-in edge ranges")
		return builtInEdgeRanges()
	}
	defer resp.Body.Close()

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if ones < 24 && !includeLarge {
			continue // skip /16 blocks by default
		}
		cidrs = append(cidrs, line)
	}
	return cidrs
}

func builtInEdgeRanges() []string {
	return []string{
		"76.76.21.0/24", "66.33.60.0/24", "64.29.17.0/24",
		"216.198.79.0/24", "64.239.109.0/24", "64.239.123.0/24",
		"216.230.84.0/24", "216.230.86.0/24", "198.169.1.0/24",
		"198.169.2.0/24", "216.150.1.0/24", "216.150.16.0/24",
	}
}

func loadFile(path string) []string {
	file, _ := os.Open(path)
	defer file.Close()
	var cidrs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}
	return cidrs
}

func estimateIPs(cidrs []string) int {
	total := 0
	for _, c := range cidrs {
		_, ipnet, _ := net.ParseCIDR(c)
		ones, _ := ipnet.Mask.Size()
		total += 1 << (32 - ones)
	}
	return total
}

func scanAll(cidrs []string, concurrency int, timeout time.Duration) []Result {
	var results []Result
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, cidr := range cidrs {
		ips, _ := ipsFromCIDR(cidr)
		for _, ip := range ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				openPorts := checkPorts(ip, timeout)
				if len(openPorts) > 0 {
					mu.Lock()
					results = append(results, Result{IP: ip, Ports: openPorts})
					mu.Unlock()
					fmt.Printf("✅ %s → HTTP server on port(s) %v\n", ip, openPorts)
				}
			}(ip)
		}
	}
	wg.Wait()
	return results
}

func checkPorts(ip string, timeout time.Duration) []int {
	open := []int{}
	for _, port := range []int{80, 443} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err == nil {
			open = append(open, port)
			conn.Close()
		}
	}
	return open
}

func ipsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func printResults(results []Result) {
	fmt.Printf("\n%d IPs with open HTTP/HTTPS ports\n", len(results))
	fmt.Printf("%-18s %s\n", "IP", "OPEN PORTS")
	fmt.Println(strings.Repeat("-", 40))
	for _, r := range results {
		fmt.Printf("%-18s %v\n", r.IP, r.Ports)
	}
}
