# Dnser
Dnser is a free and open-source subdomain guesser tool written in Go.
# Installation
```
git clone https://github.com/MachiavelliII/Dnser.git
cd Dnser
go build dnser.go
```
# Usage

```
./dnser -h
________                           
___  __ \__________________________
__  / / /_  __ \_  ___/  _ \_  ___/
_  /_/ /_  / / /(__  )/  __/  /         @MachIaVellill
/_____/ /_/ /_//____/ \___//_/     

Usage of ./dnser:
  -d string
        The domain you want to enumerate. [Required]
        Example: website.com
  -f string
        Output format: json, xml, md, or csv (default "json")
  -o string
        Output file (optional)
  -s string
        The DNS server to use.
        NOTE: Pay attention to rate limiting restrictions (default "8.8.8.8:53")
  -t int
        The amount of threads. (default 75)
  -v    Enable verbosity
  -w string
        The wordlist path to use. [Required]
         Example: /path/to/wordlist
```

https://github.com/MachiavelliII/Dnser/assets/145562237/833b5334-2b28-484f-bd61-327ea2fd42ca

