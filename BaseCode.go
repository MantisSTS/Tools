package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sync"
)

var wg sync.WaitGroup

func processJob(jobs <-chan string, results chan<- map[string]string) {
	for data := range jobs {

	}
}

func main() {
	jobs := make(chan string, 1000)
	results := make(chan map[string]string)

	threads := flag.Int("threads", 100, "Number of concurrent jobs")
	flag.Parse()

	// Make jobs
	for j := 0; j < *threads; j++ {
		wg.Add(1)
		go func(jobs <-chan string, results chan<- map[string]string) {
			defer wg.Done()
			processJob(jobs, results)
		}(jobs, results)
	}

	sc := bufio.NewScanner(os.Stdin)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for sc.Scan() {
			jobs <- sc.Text()
		}
		close(jobs)
	}()

	for res := range results {
		fmt.Println(res)
	}

	wg.Wait()
}
