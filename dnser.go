package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"

	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

func LookupCNAME(FQDN, DNSServerAddress string) ([]string, error) {
	var msg dns.Msg
	var FQDNs []string
	msg.SetQuestion(dns.Fqdn(FQDN), dns.TypeCNAME)
	In, err := dns.Exchange(&msg, DNSServerAddress)
	if err != nil {
		return FQDNs, err
	}
	if len(In.Answer) < 1 {
		return FQDNs, errors.New("No Records Found!")
	}
	for _, answer := range In.Answer {
		if C, ok := answer.(*dns.CNAME); ok {
			FQDNs = append(FQDNs, C.Target)
		}
	}
	return FQDNs, nil
}

func LookupA(FQDN, DNSServerAddress string) ([]string, error) {
	var msg dns.Msg
	var IPs []string
	msg.SetQuestion(dns.Fqdn(FQDN), dns.TypeA)
	In, err := dns.Exchange(&msg, DNSServerAddress)
	if err != nil {
		return IPs, err
	}

	if len(In.Answer) < 1 {
		return IPs, errors.New("No Records Found!")
	}

	for _, answer := range In.Answer {
		if A, ok := answer.(*dns.A); ok {
			IPs = append(IPs, A.A.String())
		}
	}
	return IPs, nil
}

func Lookup(FQDN, DNSServerAddress string, verbosity bool) []res {
	var results []res
	var cFQDN = FQDN
	for {
		cnames, err := LookupCNAME(cFQDN, DNSServerAddress)
		if err == nil && len(cnames) > 0 {
			cFQDN = cnames[0]
			continue
		}
		IPs, err := LookupA(cFQDN, DNSServerAddress)
		if err != nil {
			break
		}

		for _, IP := range IPs {
			result := res{IPAddress: IP, Hostname: FQDN}
			results = append(results, result)
			if verbosity {
				fmt.Printf("Found subdomain: %s - %s\n", FQDN, IP)
			}
		}
		break
	}
	return results
}

func thread(wg *sync.WaitGroup, FQDNs chan string, results chan []res, DNSServerAddress string, verbosity bool) {
	defer wg.Done()
	var subdomainResults []res
	for FQDN := range FQDNs {
		subdomainResults = append(subdomainResults, Lookup(FQDN, DNSServerAddress, verbosity)...)
	}
	results <- subdomainResults
}

type res struct {
	IPAddress string
	Hostname  string
}

type Output struct {
	Results []res `json:"results"`
}

func AsCIIArt() {
	var art string
	art += "________                           \n"
	art += "___  __ \\__________________________\n"
	art += "__  / / /_  __ \\_  ___/  _ \\_  ___/\n"
	art += "_  /_/ /_  / / /(__  )/  __/  /    	@MachIaVellill		\n"
	art += "/_____/ /_/ /_//____/ \\___//_/     \n"
	art += "									\n"
	color.Green(art)
}

func main() {
	AsCIIArt()
	var (
		Domain           = flag.String("d", "", "The domain you want to enumerate. [Required]\nExample: website.com")
		Wordlist         = flag.String("w", "", "The wordlist path to use. [Required]\n Example: /path/to/wordlist")
		Threads          = flag.Int("t", 75, "The amount of threads.")
		DNSServerAddress = flag.String("s", "8.8.8.8:53", "The DNS server to use.\nNOTE: Pay attention to rate limiting restrictions")
		OutputFile       = flag.String("o", "", "Output file (optional)")
		OutputFormat     = flag.String("f", "json", "Output format: json, xml, md, or csv")
		Verbosity        = flag.Bool("v", false, "Enable verbosity")
	)

	flag.Parse()

	if *Domain == "" || *Wordlist == "" || os.Args[1] == "" {
		flag.Usage()
		os.Exit(1)
	}
	// Secret Key > 8gCbXWjA2fY1GDc5JiVKveuNpGURE1GWNkvPYb5pumfUYZVJGTPGkSQ3t25
	var Enum string
	Enum += "[*] Enumerating subdomains for " + *Domain
	color.Yellow(Enum)

	var wg sync.WaitGroup
	FQDNs := make(chan string, *Threads)
	results := make(chan []res, *Threads)
	stop := make(chan struct{})

	WLValidator, err := os.Open(*Wordlist)
	if err != nil {
		panic(err)
	}
	defer WLValidator.Close()
	Scanner := bufio.NewScanner(WLValidator)

	for i := 0; i < *Threads; i++ {
		wg.Add(1)
		go thread(&wg, FQDNs, results, *DNSServerAddress, *Verbosity)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		close(stop)
	}()

	go func() {
		for Scanner.Scan() {
			select {
			case <-stop:
				return
			default:
				FQDNs <- fmt.Sprintf("%s.%s", strings.TrimSpace(Scanner.Text()), *Domain)
			}
		}
		close(FQDNs)
		wg.Wait()
		close(results)
	}()
	// b2ggSGkhCmNvb2tpZT8=
	var allResults []res

	for subdomainResults := range results {
		allResults = append(allResults, subdomainResults...)
	}

	Wri := tabwriter.NewWriter(os.Stdout, 5, 20, 8, ' ', 2)
	var Enumed string
	if len(allResults) < 1 {
		color.Red("[*] No subdomains found! Try another wordlist or it may be a rate-limit restriction")
	} else {
		Enumed += "[*] Enumerated subdomains for " + *Domain
		for _, r := range allResults {
			fmt.Fprintf(Wri, "%s\t%s\n", r.Hostname, r.IPAddress)
		}
		color.Green(Enumed)
		Wri.Flush()
		color.Green("[*] Finished")

		if *OutputFile != "" {
			switch *OutputFormat {
			case "json":
				outputData, err := json.Marshal(Output{Results: allResults})
				if err != nil {
					panic(err)
				}
				outputFile, err := os.Create(*OutputFile)
				if err != nil {
					panic(err)
				}
				defer outputFile.Close()
				_, err = outputFile.Write(outputData)
				if err != nil {
					panic(err)
				}
				color.Green("[*] Results saved to", *OutputFile)

			case "xml":
				outputData, err := xml.MarshalIndent(Output{Results: allResults}, "", "  ")
				if err != nil {
					panic(err)
				}
				outputFile, err := os.Create(*OutputFile)
				if err != nil {
					panic(err)
				}
				defer outputFile.Close()
				_, err = outputFile.Write(outputData)
				if err != nil {
					panic(err)
				}
				color.Green("[*] Results saved to", *OutputFile)

			case "md":
				fmt.Println("| Hostname | IP Address |")
				fmt.Println("| -------- | ---------- |")
				for _, r := range allResults {
					fmt.Printf("| %s | %s |\n", r.Hostname, r.IPAddress)
				}
				if *OutputFile != "" {
					outputFile, err := os.Create(*OutputFile)
					if err != nil {
						panic(err)
					}
					defer outputFile.Close()
					for _, r := range allResults {
						fmt.Fprintf(outputFile, "| %s | %s |\n", r.Hostname, r.IPAddress)
					}
					color.Green("[*] Results saved to %s", *OutputFile)
				}

			case "csv":
				if *OutputFile != "" {
					outputFile, err := os.Create(*OutputFile)
					if err != nil {
						panic(err)
					}
					defer outputFile.Close()
					fmt.Fprintf(outputFile, "Hostname,IP Address\n")
					for _, r := range allResults {
						fmt.Fprintf(outputFile, "%s,%s\n", r.Hostname, r.IPAddress)
					}
					color.Green("[*] Results saved to %s", *OutputFile)
				} else {
					fmt.Printf("Hostname,IP Address\n")
					for _, r := range allResults {
						fmt.Printf("%s,%s\n", r.Hostname, r.IPAddress)
					}
				}
			default:
				color.Red("Unsupported output format. Use 'json', 'xml', 'md', or 'csv.")
				os.Exit(1)
			}
		}
	}
}
