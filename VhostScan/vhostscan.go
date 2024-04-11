package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Results struct {
	ResponseStatus  string   `json:"ResponseStatus,omitempty"`
	Host            string   `json:"Host"`
	IP              string   `json:"IP"`
	Title           string   `json:"Title"`
	ResponseHeaders []string `json:"ResponseHeaders"`
	ResponseBody    string   `json:"ResponseBody"`
}

type Work struct {
	Domain string
	IP     string
}

var (
	resultsChan = make(chan Results, 200)
	includeBody bool
)

func main() {
	i := flag.String("i", "", "IP addresses file to read from")
	d := flag.String("d", "", "Domain names file to read from")
	v := flag.Bool("v", false, "Show verbose errors")
	ib := flag.Bool("b", false, "Include the Body of the response in the output")
	c := flag.Int("c", 10, "Number of concurrent workers")

	flag.Parse()

	if *i == "" || *d == "" {
		log.Fatal("No file specified")
	}

	if *ib {
		includeBody = true
	}

	ips, err := os.Open(*i)
	if err != nil {
		log.Fatal(err)
	}
	defer ips.Close()

	domains, err := os.Open(*d)
	if err != nil {
		log.Fatal(err)
	}
	defer domains.Close()

	domainList := getLines(domains)
	ipList := getLines(ips)

	workChan := make(chan Work, len(domainList)*len(ipList))

	go func() {
		for _, domain := range domainList {
			for _, ip := range ipList {
				workChan <- Work{Domain: domain, IP: ip}
			}
		}
		close(workChan)
	}()

	var wg sync.WaitGroup
	for i := 0; i < *c; i++ {
		wg.Add(1)
		go func() {
			for work := range workChan {
				processWork(work, *v)
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var finalResults []Results
	for res := range resultsChan {
		fmt.Printf("%s - %s\n", res.Host, res.IP)
		finalResults = append(finalResults, res)
	}

	saveResults(finalResults)
}

func getLines(f *os.File) []string {
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return lines
}

func processWork(work Work, verbose bool) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", work.IP+":443", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         work.Domain,
	})

	if err != nil {
		if verbose {
			log.Printf("Could not connect to %s: %v\n", work.IP, err)
		}
		return
	}
	defer conn.Close()

	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == work.Domain+":443" {
			addr = work.IP + ":443"
		}
		return dialer.DialContext(ctx, network, addr)
	}

	httpReq, err := http.NewRequest("GET", "https://"+work.Domain+"/", nil)
	if err != nil {
		if verbose {
			log.Printf("Could not create request: %v", err)
		}
		return
	}

	httpReq.Host = work.Domain

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		if verbose {
			log.Printf("Could not perform request: %v", err)
		}
		return
	}
	defer resp.Body.Close()

	var body string
	if includeBody {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(resp.Body)
		if err != nil {
			if verbose {
				log.Printf("Could not read response body: %v", err)
			}
		}
		body = buf.String()
	}

	res := Results{
		ResponseStatus:  resp.Status,
		Host:            work.Domain,
		IP:              work.IP,
		Title:           resp.Header.Get("Title"),
		ResponseHeaders: resp.Header["Server"],
		ResponseBody:    body,
	}

	resultsChan <- res
}

func saveResults(results []Results) {
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02_15-04-05")
	file, err := os.Create("results_" + formattedTime + ".json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := json.Marshal(results)
	if err != nil {
		log.Fatal(err)
	}

	_, err = file.Write(data)
	if err != nil {
		log.Fatal(err)
	}
}
