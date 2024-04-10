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
var rg sync.WaitGroup
var threads int

func doLookup(domain string, results chan<- map[string]net.IP) {
	addr, err := net.LookupIP(domain)
	if err == nil {
		res := make(map[string]net.IP)
		for _, ip := range addr {
			res[domain] = ip
			results <- res
		}
	} else {
		res := make(map[string]net.IP)
		res['domain'] = nil
		results <- res
	}
}

func processJob(jobs <-chan string, results chan<- map[string]net.IP, wg *sync.WaitGroup) {
	for data := range jobs {
		doLookup(data, results)
	}
	wg.Done()
}

func readResults(results <-chan map[string]net.IP, rg *sync.WaitGroup) {
	for res := range results {
		for dom, ip := range res {
			fmt.Printf("%s - %s\n", dom, ip)
			// delete(res, dom)
		}
	}
	rg.Done()
}

func main() {
	flag.IntVar(&threads, "t", 30, "Number of concurrent jobs")
	flag.Parse()

	results := make(chan map[string]net.IP, 100)
	jobs := make(chan string, 100)

	sc := bufio.NewScanner(os.Stdin)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for sc.Scan() {
			jobs <- sc.Text()
		}
		close(jobs)
	}()

	// Create jobs
	for j := 0; j < threads; j++ {
		wg.Add(1)
		go processJob(jobs, results, &wg)
	}

	// Read Results
	rg.Add(1)
	go readResults(results, &rg)

	wg.Wait()
	close(results)
	rg.Wait()

}
