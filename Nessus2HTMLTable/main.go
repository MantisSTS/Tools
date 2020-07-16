package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

type reportHost struct {
	HostName    string       `xml:"name,attr"`
	ReportItems []reportItem `xml:"ReportItem"`
}

type reportItem struct {
	PluginName     string `xml:"plugin_name"`
	Recommendation string `xml:"compliance-solution"`
	Title          string `xml:"compliance-check-name"`
	Status         string `xml:"compliance-result"`
}

func main() {
	var filename string
	flag.StringVar(&filename, "i", "", "The Nessus csv file")
	flag.Parse()

	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	defer file.Close()

	decoder := xml.NewDecoder(file)

	for {

		token, err := decoder.Token()

		if err != nil {
			break
		}

		if token == nil {
			break
		}

		switch element := token.(type) {
		case xml.StartElement:
			tagName := element.Name.Local

			// Read the ReportHosts from the XML
			if tagName == "ReportHost" {

				var host reportHost
				decoder.DecodeElement(&host, &element)
				html := `<html>
				<head></head>
				<body>
				<table>
					<thead>
					<tr>
						<th>Title</th>
						<th>Recommendation</th>
						<th>Status</th>
					</tr>
				</thead>
				<tbody>`

				for _, item := range host.ReportItems {
					if strings.Contains(item.PluginName, "Compliance Checks") {
						if item.Status == "FAILED" {
							row := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", item.Title, item.Recommendation, item.Status)
							html += row
						}
					}
				}
				html += "</tbody></table></body></html>"
				fmt.Println(html)
			}
		}
	}
}
