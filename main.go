package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-10-01/network"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"log"
)

func init() {
	if len(os.Args) != 3 || len(os.Args[1]) < 1{
		fmt.Println("Usage: ./nsgrules  <rule name> <new ip>")
		os.Exit(-1)
	}
}

func main() {

	idRegex := regexp.MustCompile(`/subscriptions/.*/resourceGroups/(.*)/providers/.*`)

	// details we need to modify.
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	inRuleName := os.Args[1]
	newIP := os.Args[2]

	a, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		log.Fatalf("Unable to create initialiser!!! %v\n", err)
	}

	client := network.NewSecurityGroupsClient(subscriptionID)
	client.Authorizer = a

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()
	sgList, err := client.ListAll(ctx)
	if err != nil {
		log.Fatalf("error during list %v\n", err)
	}

	for _, sg := range sgList.Values() {
		fmt.Printf("securitygroup name %s\n", *sg.Name)

		for _, sr := range *sg.SecurityRules {
			if *sr.Name == inRuleName {

				rg := ""
				res := idRegex.FindStringSubmatch(*sr.ID)
				if res != nil && len(res) == 2 {
					rg = res[1]
				}

				fmt.Printf("got match for rule %s\n", *sr.Name)
				fmt.Printf("current addr %s\n", *sr.SourceAddressPrefix)
				*sr.SourceAddressPrefix = newIP
				fmt.Printf("new addr %s\n", newIP)

				client.CreateOrUpdate(ctx, rg, *sg.Name, sg)
			}
		}
	}

}
