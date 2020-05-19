package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
)

var wg sync.WaitGroup
var threads int
var goFaster bool

func doLookup(domain string, results chan<- map[string]net.IP) {
	addr, err := net.LookupIP(domain)
	if err == nil {
		res := make(map[string]net.IP)
		for _, ip := range addr {
			res[domain] = ip
			results <- res
		}
	}
}

func processJob(jobs <-chan string, results chan<- map[string]net.IP) {
	for data := range jobs {
		if goFaster {
			wg.Add(1)
			go func() {
				defer wg.Done()
				doLookup(data, results)
			}()
		} else {
			doLookup(data, results)
		}
	}
}

func main() {
	flag.IntVar(&threads, "t", 30, "Number of concurrent jobs")
	flag.BoolVar(&goFaster, "f", false, "I love the chaos")
	flag.Parse()

	results := make(chan map[string]net.IP, 2000)
	jobs := make(chan string, 2000)

	sc := bufio.NewScanner(os.Stdin)

	// Create jobs
	for j := 0; j < threads; j++ {
		wg.Add(1)
		go func(jobs chan string, results chan map[string]net.IP) {
			defer wg.Done()
			processJob(jobs, results)
		}(jobs, results)
	}

	// Read data into jobs channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		for sc.Scan() {
			jobs <- sc.Text()
		}
		close(jobs)
	}()

	for res := range results {
		for dom, ip := range res {
			fmt.Printf("%s - %s\n", dom, ip)
		}
	}
	wg.Wait()
	close(results)
}
