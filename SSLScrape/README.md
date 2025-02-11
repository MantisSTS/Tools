# ScrapeSSL

## Description
This tool can be used to grab the SSL certificate's CommonNames from a range of IP addresses

## Install
You can install this using `go get` or by running `go build .` 
```
$ go install -v github.com/MantisSTS/Tools/SSLScrape@latest
```
or
```
$ git clone https://github.com/MantisSTS/Tools.git MantisTools
$ cd MantisTools/SSLScrape
$ go build .
```

## Usage
```
$ echo "192.168.0.0/24" | SSLScrape | sort -u | tee -a unique_CNs.log
```
