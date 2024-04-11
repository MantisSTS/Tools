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
	ResponseStatus  string `json:omitempty`
	Host            string
	IP              string
	Title           string
	ResponseHeaders []string
	ResponseBody    string
}

var (
	finalResults []Results
	includeBody  bool
)

func main() {
	// Todo: add a concurrency count

	i := flag.String("i", "", "IP addresses file to read from")
	d := flag.String("d", "", "Domain names file to read from")
	v := flag.Bool("v", false, "Show verbose errors")
	ib := flag.Bool("b", false, "Include the Body of the response in the output")

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

	var resultsChan = make(chan Results, 200)

	defer domains.Close()

	scanner := bufio.NewScanner(domains)

	var domainList []string
	// var results []Results
	for scanner.Scan() {

		domain := scanner.Text()
		domain = strings.TrimSpace(domain)

		if domain == "" {
			continue
		}
		domainList = append(domainList, domain)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	ipScanner := bufio.NewScanner(ips)
	var ipList []string
	for ipScanner.Scan() {
		ip := ipScanner.Text()
		ip = strings.TrimSpace(ip)

		if ip == "" {
			continue
		}

		ipList = append(ipList, ip)
	}
	if err := ipScanner.Err(); err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	// Todo: This should be channel
	for _, domain := range domainList {

		// Todo: This should be channel
		for _, ip := range ipList {

			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}

			wg.Add(1)
			// Todo: this should be a real function
			go func() {

				defer wg.Done()

				conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         domain,
				})

				if err != nil {
					if *v {
						log.Printf("Could not connect to %s: %v\n", ip, err)
					}
					return
				}

				defer conn.Close()

				http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					if addr == domain+":443" {
						addr = ip + ":443"
					}
					return dialer.DialContext(ctx, network, addr)
				}

				// Perform http request
				httpReq, err := http.NewRequest("GET", "https://"+domain+"/", nil)
				if err != nil {
					if *v {
						log.Printf("Could not create request: %v", err)
					}
					return
				}

				httpReq.Host = domain

				resp, err := http.DefaultClient.Do(httpReq)
				if err != nil {
					if *v {
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
						if *v {
							log.Printf("Could not read response body: %v", err)
						}
					}
					body = buf.String()
				}

				res := Results{
					ResponseStatus:  resp.Status,
					Host:            domain,
					IP:              ip,
					Title:           resp.Header.Get("Title"),
					ResponseHeaders: resp.Header["Server"],
					ResponseBody:    body,
				}

				resultsChan <- res

				finalResults = append(finalResults, Results{
					ResponseStatus:  resp.Status,
					Host:            domain,
					IP:              ip,
					Title:           resp.Header.Get("Title"),
					ResponseHeaders: resp.Header["Server"],
					ResponseBody:    body,
				})
			}()
		}
	}

	for res := range resultsChan {
		fmt.Printf("%s - %s\n", res.Host, res.IP)
	}

	wg.Wait()
	close(resultsChan)

	// Get current time
	currentTime := time.Now()

	// Format the current time to desired format
	formattedTime := currentTime.Format("2006-01-02_15-04-05")

	// Create a new file with the current time in the name
	file, err := os.Create("results_" + formattedTime + ".json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Convert the finalResults slice to JSON
	data, err := json.Marshal(finalResults)
	if err != nil {
		log.Fatal(err)
	}

	// Write the JSON data to the file
	_, err = file.Write(data)
	if err != nil {
		log.Fatal(err)
	}
}
