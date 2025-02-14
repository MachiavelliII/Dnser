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

var outputMutex sync.Mutex

func LookupCNAME(FQDN string, DNSServers []string, verbosity int) ([]string, error) {
	var FQDNs []string
	var lastErr error
	for _, server := range DNSServers {
		var msg dns.Msg
		msg.SetQuestion(dns.Fqdn(FQDN), dns.TypeCNAME)
		In, err := dns.Exchange(&msg, server)
		if err != nil {
			lastErr = err
			if verbosity >= 2 {
				outputMutex.Lock()
				color.Yellow("[DNS Error] %s @ %s: %v", FQDN, server, err)
				outputMutex.Unlock()
			}
			continue
		}
		if len(In.Answer) < 1 {
			lastErr = errors.New("no records found")
			continue
		}
		for _, answer := range In.Answer {
			if C, ok := answer.(*dns.CNAME); ok {
				FQDNs = append(FQDNs, C.Target)
			}
		}
		return FQDNs, nil
	}
	return nil, lastErr
}

func LookupA(FQDN string, DNSServers []string, verbosity int) ([]string, error) {
	var IPs []string
	var lastErr error
	for _, server := range DNSServers {
		var msg dns.Msg
		msg.SetQuestion(dns.Fqdn(FQDN), dns.TypeA)
		In, err := dns.Exchange(&msg, server)
		if err != nil {
			lastErr = err
			if verbosity >= 2 {
				outputMutex.Lock()
				color.Yellow("[DNS Error] %s @ %s: %v", FQDN, server, err)
				outputMutex.Unlock()
			}
			continue
		}
		if len(In.Answer) < 1 {
			lastErr = errors.New("no records found")
			continue
		}
		for _, answer := range In.Answer {
			if A, ok := answer.(*dns.A); ok {
				IPs = append(IPs, A.A.String())
			}
		}
		return IPs, nil
	}
	return nil, lastErr
}

func Lookup(FQDN string, DNSServers []string, verbosity int) []res {
	var results []res
	var cFQDN = FQDN
	for {
		cnames, err := LookupCNAME(cFQDN, DNSServers, verbosity)
		if err == nil && len(cnames) > 0 {
			cFQDN = cnames[0]
			continue
		}
		IPs, err := LookupA(cFQDN, DNSServers, verbosity)
		if err != nil {
			break
		}

		for _, IP := range IPs {
			result := res{IPAddress: IP, Hostname: FQDN}
			results = append(results, result)
			if verbosity >= 1 {
				outputMutex.Lock()
				color.Cyan("[Found Subdomain] %s -> %s", FQDN, IP)
				outputMutex.Unlock()
			}
		}
		break
	}
	return results
}

func thread(wg *sync.WaitGroup, FQDNs chan string, results chan []res, DNSServers []string, verbosity int) {
	defer wg.Done()
	var subdomainResults []res
	for FQDN := range FQDNs {
		subdomainResults = append(subdomainResults, Lookup(FQDN, DNSServers, verbosity)...)
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
	color.NoColor = false
	AsCIIArt()
	var (
		Domain       = flag.String("d", "", "The domain to enumerate (required)")
		Wordlist     = flag.String("w", "", "Wordlist path (required)")
		Threads      = flag.Int("t", 75, "Number of threads")
		DNSServers   = flag.String("s", "8.8.8.8:53,1.1.1.1:53", "Comma-separated DNS servers")
		OutputFile   = flag.String("o", "", "Output file (optional)")
		OutputFormat = flag.String("f", "json", "Output format: json, xml, md, csv")
		Verbosity    = flag.Int("v", 0, "Verbosity level: 0 [Silent], 1 [Show found subdomains], 2 [Show found subdomains and errors]")
	)

	flag.Parse()

	if *Domain == "" || *Wordlist == "" || os.Args[1] == "" {
		flag.Usage()
		os.Exit(1)
	}

	servers := strings.Split(*DNSServers, ",")
	validServers := make([]string, 0)
	for _, s := range servers {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			validServers = append(validServers, trimmed)
		}
	}
	if len(validServers) == 0 {
		outputMutex.Lock()
		color.Red("[!] No valid DNS servers provided")
		outputMutex.Unlock()
		os.Exit(1)
	}

	outputMutex.Lock()
	switch *Verbosity {
	case 0:
		color.Yellow("[*] Verbosity level: %d [Silent]", *Verbosity)
	case 1:
		color.Yellow("[*] Verbosity level: %d [Show found subdomains]", *Verbosity)
	default:
		color.Yellow("[*] Verbosity level: %d [Show found subdomains and errors]", *Verbosity)
		color.Yellow("[*] Using DNS servers: %v", validServers)
	}
	outputMutex.Unlock()

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
		go thread(&wg, FQDNs, results, validServers, *Verbosity)
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

	var allResults []res
	for subdomainResults := range results {
		allResults = append(allResults, subdomainResults...)
	}

	Wri := tabwriter.NewWriter(os.Stdout, 5, 20, 8, ' ', 2)
	if len(allResults) < 1 {
		outputMutex.Lock()
		color.Red("[!] No subdomains found")
		outputMutex.Unlock()
	} else {
		outputMutex.Lock()
		color.Green("[+] Found %d results", len(allResults))
		outputMutex.Unlock()
		for _, r := range allResults {
			fmt.Fprintf(Wri, "%s\t%s\n", r.Hostname, r.IPAddress)
		}
		Wri.Flush()
	}

	if *OutputFile != "" {
		switch *OutputFormat {
		case "json":
			outputData, err := json.Marshal(Output{Results: allResults})
			if err != nil {
				panic(err)
			}
			os.WriteFile(*OutputFile, outputData, 0644)
		case "xml":
			outputData, err := xml.MarshalIndent(Output{Results: allResults}, "", "  ")
			if err != nil {
				panic(err)
			}
			os.WriteFile(*OutputFile, outputData, 0644)
		case "md":
			content := "| Hostname | IP Address |\n| -------- | ---------- |\n"
			for _, r := range allResults {
				content += fmt.Sprintf("| %s | %s |\n", r.Hostname, r.IPAddress)
			}
			os.WriteFile(*OutputFile, []byte(content), 0644)
		case "csv":
			content := "Hostname,IP Address\n"
			for _, r := range allResults {
				content += fmt.Sprintf("%s,%s\n", r.Hostname, r.IPAddress)
			}
			os.WriteFile(*OutputFile, []byte(content), 0644)
		default:
			outputMutex.Lock()
			color.Red("[!] Unsupported output format")
			outputMutex.Unlock()
			os.Exit(1)
		}
		outputMutex.Lock()
		color.Green("[+] Results saved to %s", *OutputFile)
		outputMutex.Unlock()
	}
}
