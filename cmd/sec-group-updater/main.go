package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
)

func main() {
	//Parse commandline flags
	var sg, tag string
	var deleteFlag bool
	var port int
	flag.StringVar(&sg, "sec-groups", "", "comma separated list of security groups if not set all security groups are scanned for tag")
	flag.StringVar(&tag, "tag", "", "description tag for ingress rule to be added")
	flag.IntVar(&port, "port", 22, "port to open")
	flag.BoolVar(&deleteFlag, "delete", true, "delete ingress rule with description tag before setting new")
	flag.Parse()
	securityGroups := strings.Split(sg, ",")
	if tag == "" {
		fmt.Print("No tag provided user the --tag flag\n")
		os.Exit(-1)
	}

	//Using https://api.ipify.org to get your IP-address
	ip, err := findMyIP()
	if err != nil {
		log.Fatalf("Error while fetching IP-address %+v", err)
	}

	fmt.Printf("Update rules with CIDR %s/32\n", ip)

	//Create session and fetch all security groups connected to the project. Using credentials in ~.aws/credentials
	svc := createSession()
	sgs, err := fetchSecurityGroups(svc)
	if err != nil {
		log.Fatalf("[ERROR] %+v", err)
	}

	//looking for security groups that match the provided names. if a match is found current ingress rules is deleted and a new one is created with your new ip
	for _, v := range sgs {
		if inArray(aws.StringValue(v.GroupName), securityGroups) || len(securityGroups) == 0 {
			if deleteFlag {
				if err := deleteIPRange(v.GroupName, tag, int64(port), svc, v.IpPermissions); err != nil {
					log.Fatalf("Error while deleting ip-range %+v", err)
				}
			}
			if err := auth(ip, int64(port), v.GroupName, svc); err != nil {
				log.Fatalf("Error while adding ip-range %+v", err)
			}
		}
	}
	fmt.Printf("Ingess rules updated\n")
}

func inArray(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func findMyIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(ip), nil
}
