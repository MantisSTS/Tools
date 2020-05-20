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
	"sync"
	"time"
)

// Todo:
//	1. Specify ports to check on (443, 8443, etc)

var wg sync.WaitGroup

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parseIPs(ips string) ([]string, error) {
	var ret []string
	var err error
	ip := net.ParseIP(ips)
	if ip == nil {
		ip, ipnet, err := net.ParseCIDR(ips)
		if err != nil {
			log.Println(err)
		} else {
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				d := fmt.Sprintf("%s", net.IP.String(ip))
				ret = append(ret, d)
			}
		}
	} else {
		ret = append(ret, net.IP.String(ip))
	}

	return ret, err
}

func doRequest(ip string, results chan<- string) {
	res, err := parseIPs(ip)
	if err != nil {
		log.Println(err)
	} else {
		client := &http.Client{
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout:   time.Duration(10) * time.Second,
					KeepAlive: time.Duration(10) * time.Second,
				}).Dial,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		for _, ipr := range res {
			u := fmt.Sprintf("https://%s", string(ipr))
			dest, err := url.Parse(u)
			fmt.Println(dest)
			if err == nil {
				resp, _ := client.Get(dest.String())
				for _, e := range resp.TLS.PeerCertificates {
					for _, dns := range (*e).DNSNames {
						results <- dns
					}
				}
			}
		}
	}
}

func processJob(jobs <-chan string, results chan<- string) {
	for data := range jobs {
		doRequest(data, results)
	}
}

func main() {
	jobs := make(chan string, 1000)
	results := make(chan string)

	var threads int
	flag.IntVar(&threads, "t", 100, "Number of concurrent jobs")
	flag.Parse()

	sc := bufio.NewScanner(os.Stdin)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for sc.Scan() {
			jobs <- sc.Text()
		}
		close(jobs)
	}()

	// Make jobs
	for j := 0; j < threads; j++ {
		wg.Add(1)
		go func(jobs <-chan string, results chan<- string) {
			defer wg.Done()
			processJob(jobs, results)
		}(jobs, results)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for res := range results {
			fmt.Println(res)
		}
	}()

	wg.Wait()
}
