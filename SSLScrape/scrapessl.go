package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Global Variables
var verbose bool
var threads int
var ports []string

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// parseIPs expands CIDR ranges into a list of IPs or returns a single IP
func parseIPs(input string) ([]string, error) {
	var ips []string
	if ip := net.ParseIP(input); ip != nil {
		// It's a single IP
		ips = append(ips, ip.String())
	} else {
		// It's a CIDR range
		ip, ipnet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, err
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}

// doRequest makes HTTPS requests to the given IP on specified ports
func doRequest(ip string, results chan<- string) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, port := range ports {
		urlStr := fmt.Sprintf("https://%s:%s", ip, port)
		dest, err := url.Parse(urlStr)
		if err != nil {
			log.Println("Error parsing URL:", err)
			continue
		}

		if verbose {
			log.Println("Checking:", dest.String())
		}

		resp, err := client.Get(dest.String())
		if err != nil {
			log.Println("Request failed:", err)
			continue
		}
		resp.Body.Close()

		if resp.TLS != nil {
			for _, cert := range resp.TLS.PeerCertificates {
				for _, dns := range cert.DNSNames {
					results <- dns
				}
			}
		}
	}
}

// processJob handles input jobs, expanding CIDR if necessary
func processJob(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for data := range jobs {
		ips, err := parseIPs(data)
		if err != nil {
			log.Println("Invalid input:", data, err)
			continue
		}
		for _, ip := range ips {
			doRequest(ip, results)
		}
	}
}

// readResults prints results to stdout
func readResults(results <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for res := range results {
		fmt.Println(res)
	}
}

func main() {
	jobs := make(chan string, 1000)
	results := make(chan string)

	flag.IntVar(&threads, "t", 100, "Number of concurrent jobs")
	flag.BoolVar(&verbose, "v", false, "Set verbose mode on")

	// New Feature: Specify ports
	portStr := flag.String("p", "443", "Comma-separated list of ports to check (e.g., 443,8443)")
	flag.Parse()

	// Convert port string to slice
	ports = strings.Split(*portStr, ",")

	var jobsWg sync.WaitGroup
	var resultsWg sync.WaitGroup

	sc := bufio.NewScanner(os.Stdin)

	// Read input and push to jobs channel
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for sc.Scan() {
			jobs <- sc.Text()
		}
		close(jobs)
	}()

	// Start worker threads
	for j := 0; j < threads; j++ {
		jobsWg.Add(1)
		go processJob(jobs, results, &jobsWg)
	}

	resultsWg.Add(1)
	go readResults(results, &resultsWg)

	jobsWg.Wait()
	close(results)
	resultsWg.Wait()
}
