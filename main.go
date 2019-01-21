package main

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-10-01/network"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"log"
)

func init() {
	if len(os.Args) != 3 || len(os.Args[1]) < 1{
		fmt.Println("Usage: ./nsgrules  <rule name> <new ip>")
		os.Exit(-1)
	}
}

func listResourceGroups(  subscriptionID string, auth autorest.Authorizer ) ([]string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()

	fmt.Printf("making client")
	grClient := resources.NewGroupsClient(subscriptionID)
	grClient.Authorizer = auth
	tab := make([]string, 0)

	for list, err := grClient.ListComplete(context.Background(), "", nil); list.NotDone(); err = list.Next() {
		if err != nil {
			return nil, errors.Wrap(err, "error traverising RG list")
		}
		rgName := *list.Value().Name
		tab = append(tab, rgName)
		fmt.Printf("rg %s\n", rgName)
	}

	grClient.Get(ctx, "")

	return tab, nil
}


func main() {

	// details we need to modify.
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	inRuleName := os.Args[1]
	newIP := os.Args[2]

	a, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		log.Fatalf("Unable to create initialiser!!! %v\n", err)
	}

	l, err := listResourceGroups(subscriptionID, a)
	if err != nil {
		log.Fatal("Unable to list resource groups %v\n", err)
	}

	for _,rgName := range l {
		fmt.Printf("checking rg %s\n", rgName)
		client := network.NewSecurityGroupsClient(subscriptionID)
		client.Authorizer = a

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
		defer cancel()
		sList, err := client.List(ctx, rgName)
		if err != nil {
			log.Fatalf("error during list %v\n", err)
		}

		for _, s := range sList.Values() {
			fmt.Printf("securitygroup name %s\n", *s.Name)

			sg, err := client.Get(ctx, rgName, *s.Name, "")
			if err != nil {
				log.Fatalf("error during security group get %v\n", err)
			}

			for _, sr := range *sg.SecurityRules {
				if *sr.Name == inRuleName {
					fmt.Printf("got match for rule %s!\n", *s.Name)
					fmt.Printf("current addr %s\n", *sr.SourceAddressPrefix)
					*sr.SourceAddressPrefix = newIP

					client.CreateOrUpdate(ctx, rgName, *s.Name, sg)
				}

			}
		}
	}

}
