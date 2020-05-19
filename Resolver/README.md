- [Resolver](#resolver)
  - [Description](#description)
  - [Install](#install)
  - [Usage](#usage)
  - [Contribute?](#contribute)

# Resolver

## Description
There are lots of times when I want to resolve a whole list of domains to IP addresses without writing a huge bash one-liner. So therefore I created this little script just so I can pipe the domains to it and `tee` them to a file.

## Install 

`go build .`

## Usage

Once built you can just run it like this:

`cat domains.txt | ./resolver | tee -a resolved.txt`


## Contribute?
Feel free to submit pull requests or submit issues if you have an idea or need a bug fixed.