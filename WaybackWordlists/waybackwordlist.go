package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	var results []map[string]int

	jobsChan := make(chan string, 1000)

	var numberOfItems int
	flag.IntVar(&numberOfItems, "p", 10, "Only return the entries which occur p-times")
	flag.Parse()

	sc := bufio.NewScanner(os.Stdin)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for sc.Scan() {
			jobsChan <- sc.Text()
		}
		close(jobsChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		tempResults := map[string]int{}
		for item := range jobsChan {

			item = strings.TrimSpace(item)

			if item == "" {
				continue
			}

			count := 0
			if val, ok := tempResults[item]; ok {
				count = val + 1
				tempResults[item] = count
			} else {
				count = 1
				tempResults[item] = count
			}
		}
		results = append(results, tempResults)
	}()

	wg.Wait()

	for _, res := range results {
		for k, v := range res {
			if v >= numberOfItems {
				fmt.Println(k)
			}
		}
	}
}
