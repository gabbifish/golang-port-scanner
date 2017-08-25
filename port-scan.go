package main

import (
  "flag"
  "fmt"
  "bufio"
  "strings"
  "strconv"
  "os"
  "net"
  "time"
)

type scanParams struct {
    ports []int
    ips []string
    protocols []string
}

func main() {
    portsPtr := flag.String("ports", "1-1024", "A single port number or range of port numbers, formatted 'start-end'.")
    ipPtr := flag.String("ip", "", "The IP address to scan.")
    filePtr := flag.String("file", "", "A filename containing a list of IP addresses to scan, separated by newlines.")
    transportPtr := flag.String("transport", "TCP/UDP", "Either of three strings 'TCP', 'UDP', and 'TCP/UDP', specifying which type of port you want to scan. Default is both.")
    flag.Parse()

    params := handleInputs(portsPtr, ipPtr, filePtr, transportPtr)
    scan(params)
}

func handleInputs(portsPtr, ipPtr, filePtr, transportPtr *string) *scanParams {
    // Process port range input
    portsStr := strings.Split(*portsPtr, "-")
    portsInt := make([]int, len(portsStr))
    for i := range portsInt {
        portTemp, err := strconv.Atoi(portsStr[i])
        portsInt[i] = portTemp
        checkError(err)
    }

    // Process IP input
    var ipsStr []string
    if *ipPtr == "" && *filePtr == "" {
      fmt.Println("You must either specify an IP to scan or a file with multiple newline seperated IPs.")
      os.Exit(1)
    }
    if *ipPtr != "" {
      ipsStr = append(ipsStr, *ipPtr)
    }
    if *filePtr != "" {
      ipFile, err := os.Open(*filePtr)
      checkError(err)
      defer ipFile.Close()
      scanner := bufio.NewScanner(ipFile)
      scanner.Split(bufio.ScanLines)
      for scanner.Scan() {
        ipsStr = append(ipsStr, scanner.Text())
      }
    }

    // Process TCP/UDP specification
    protocolsStr := strings.Split(*transportPtr, "/")

    // Populate configs struct with inputs parsed above
    configs := &scanParams{ports: portsInt, ips: ipsStr, protocols: protocolsStr}
    return configs
}

func scan(params * scanParams) {
    scanJobs := make(chan string, 100)
    scanResults := make(chan string, 100)

    // Launch scan workers
    for w := 0; w < 50; w++ {
        go scanWorker(w, scanJobs, scanResults)
    }

    // Populate scanJobs channel with scan information.
    for _, tIp := range params.ips {
        for tPort := params.ports[0]; tPort <= params.ports[1]; tPort++ {
            portNum := strconv.Itoa(tPort)
            target := tIp + ":" + portNum
            scanJobs<-target
        }
    }
    close(scanJobs)

    for {
        select {
        case result := <-scanResults:
            resultArray := strings.Split(result, ":")
            openIP, openPort, protocol := resultArray[0], resultArray[1], resultArray[2]
            fmt.Printf("Address %s has port %s open for protocol %s \n", openIP, openPort, protocol)
        case <- time.After(time.Duration(1) * time.Second):
            goto AfterLoop
        }
    }
AfterLoop:
    close(scanResults)
}

func scanWorker(id int, target <-chan string, results chan<- string){
    // Use DialTimeout instead?
    for currTarget := range target {
        connTCP, errTCP := net.DialTimeout("tcp", currTarget, time.Duration(500)*time.Millisecond)
        if errTCP == nil {
            connTCP.Close()
            result := currTarget + ":TCP"
            results <- result
        }
    }
}

func checkError(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
        os.Exit(1)
    }
}
