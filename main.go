package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
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
		if inArray(aws.StringValue(v.GroupName), securityGroups) {
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

func fetchSecurityGroups(svc *ec2.EC2) ([]*ec2.SecurityGroup, error) {
	sc, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to describe VPCs, %v", err))
	}
	if len(sc.SecurityGroups) == 0 {
		return nil, errors.New("No VPCs found needle")
	}
	return sc.SecurityGroups, nil
}
func createSession() *ec2.EC2 {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	return ec2.New(sess)
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
func deleteIPRange(groupName *string, tag string, port int64, svc *ec2.EC2, ipPermissions []*ec2.IpPermission) error {
	for _, v := range ipPermissions {
		if aws.Int64Value(v.FromPort) == port {
			for _, v2 := range v.IpRanges {
				if aws.StringValue(v2.Description) == tag {
					fmt.Printf("Tag %s found in %s with ip-range %s\n", aws.StringValue(v2.Description), aws.StringValue(groupName), aws.StringValue(v2.CidrIp))
					err := deAuth(groupName, v2.CidrIp, port, svc)
					if err != nil {
						return err
					}
					fmt.Printf("IP-range %s deleted in group %s\n", aws.StringValue(v2.CidrIp), aws.StringValue(groupName))
				}
			}
		}
	}
	return nil
}
func deAuth(groupName, cidrIP *string, port int64, svc *ec2.EC2) error {
	input := &ec2.RevokeSecurityGroupIngressInput{
		CidrIp:     cidrIP,
		ToPort:     aws.Int64(port),
		FromPort:   aws.Int64(port),
		GroupName:  groupName,
		IpProtocol: aws.String("tcp"),
	}
	_, err := svc.RevokeSecurityGroupIngress(input)
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to revoke security group %v ingress, %v", cidrIP, err))
	}
	return nil
}

func auth(ip string, port int64, groupName *string, svc *ec2.EC2) error {
	_, err := svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupName: groupName,
		IpPermissions: []*ec2.IpPermission{
			// Can use setters to simplify seting multiple values without the
			// needing to use aws.String or associated helper utilities.
			(&ec2.IpPermission{}).
				SetIpProtocol("tcp").
				SetFromPort(port).
				SetToPort(port).
				SetIpRanges([]*ec2.IpRange{
					{
						Description: aws.String("oskar mobile"),
						CidrIp:      aws.String(ip + "/32"),
					},
				}),
		},
	})
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to set security group %v ingress, %v", groupName, err))
	}
	fmt.Printf("IP-range %s/32 port %d added in group %s\n", ip, port, aws.StringValue(groupName))
	return nil
}
