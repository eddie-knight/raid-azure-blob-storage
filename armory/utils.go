package armory

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/privateerproj/privateer-sdk/raidengine"
	"github.com/privateerproj/privateer-sdk/utils"
)

func ValidateVariableValue(variableValue string, regex string) (bool, error) {
	// Check if variable matches regex
	matched, err := regexp.MatchString(regex, variableValue)

	if err != nil {
		return false, fmt.Errorf("validation of variable has failed with message: %s", err)
	}

	if !matched {
		return false, fmt.Errorf("variable value is not valid")
	}

	return true, nil
}

// MakeGETRequest makes a GET request to the specified endpoint and returns the status code
func MakeGETRequest(endpoint string, token string, result *raidengine.MovementResult, minTlsVersion *int, maxTlsVersion *int) *http.Response {
	// Add query parameters to request URL
	endpoint = endpoint + "?comp=list"

	// If specific TLS versions are provided, configure the TLS version
	tlsConfig := &tls.Config{}
	if minTlsVersion != nil {
		tlsConfig.MinVersion = uint16(*minTlsVersion)
	}

	if maxTlsVersion != nil {
		tlsConfig.MaxVersion = uint16(*maxTlsVersion)
	}

	// Create an HTTP client with a timeout and the specified TLS configuration
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Create a new GET request
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		result.Passed = false
		result.Message = err.Error()
		return nil
	}

	// Set the required headers
	req.Header.Set("x-ms-version", "2025-01-05")
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Make the GET request
	response, err := client.Do(req)
	if err != nil {
		result.Passed = false
		result.Message = err.Error()
		return response
	}
	defer response.Body.Close()

	return response
}

// CheckStatusCode checks the TLS version of the response and updates the result
func CheckTLSVersion(endpoint string, token string, result *raidengine.MovementResult) {

	// Set the minimum TLS version to TLS 1.0
	minTlsVersion := tls.VersionTLS10

	response := MakeGETRequest(endpoint, token, result, &minTlsVersion, nil)

	// Check if the connection used TLS
	if response.TLS != nil {
		tlsVersion := response.TLS.Version
		// Map TLS version to human-readable format
		switch tlsVersion {
		case 0x0304:
			result.Message = "TLS 1.3 is being used"
			result.Passed = true
		case 0x0303:
			result.Message = "TLS 1.2 is being used"
			result.Passed = true
		case 0x0302:
			result.Message = "TLS 1.1 is being used"
			result.Passed = false
		case 0x0301:
			result.Message = "TLS 1.0 is being used"
			result.Passed = false
		default:
			result.Message = "error: Unknown TLS version"
			result.Passed = false
		}
	} else {
		result.Message = "error: No TLS information found in response"
		result.Passed = false
	}
}

func ConfirmHTTPRequestFails(endpoint string, result *raidengine.MovementResult) {
	httpUrl := strings.Replace(endpoint, "https", "http", 1)
	response := MakeGETRequest(httpUrl, "", result, nil, nil)
	if result.Passed {
		if response.StatusCode == 400 && strings.Contains(response.Status, "http") {
			result.Message = "HTTP requests are not supported"
		} else {
			result.Passed = false
			result.Message = "HTTP requests are supported"
		}
	}
}

func ConfirmOutdatedProtocolRequestsFail(endpoint string, result *raidengine.MovementResult, tlsVersion int) {

	response := MakeGETRequest(endpoint, "", result, &tlsVersion, &tlsVersion)

	if response == nil {
		result.Passed = false
		result.Message = fmt.Sprintf("Request unexpectedly failed with error: %x", result.Message)
	} else {
		if response.StatusCode == http.StatusBadRequest && strings.Contains(response.Status, "TLS version") {
			result.Passed = true
			result.Message = fmt.Sprintf("Insecure TLS version %s not supported", tls.VersionName(uint16(tlsVersion)))
		} else {
			result.Passed = false
			result.Message = fmt.Sprintf("Insecure TLS version %s is supported", tls.VersionName(uint16(tlsVersion)))
		}
	}
}

/* GlobalVars Lazy Loaders */

func (g *GlobalVars) getCred() *azidentity.DefaultAzureCredential {
	if g.cred == nil {
		var err error
		g.cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			g.err = fmt.Errorf("failed to get Azure credential: %v", err)
		}
	}
	return g.cred
}

func (g *GlobalVars) getToken(result *raidengine.MovementResult) string {
	if g.token.Token == "" || g.token.ExpiresOn.Before(time.Now().Add(-5*time.Minute)) {
		var err error
		g.token, err = g.getCred().GetToken(context.Background(), policy.TokenRequestOptions{
			Scopes: []string{"https://storage.azure.com/.default"},
		})
		if err != nil {
			result.Message = fmt.Sprintf("Failed to get access token: %v", err)
			return ""
		}
	}
	return g.token.Token
}

func (g *GlobalVars) getStorageAccount() StorageAccount {
	if g.storageAccount.Id == "" {
		// Get storage account resource ID
		g.storageAccount.Id = utils.GetRequiredString("raids.ABS.storageAccountResourceId", nil)
		if valid, err := ValidateVariableValue(g.storageAccount.Id, `^/subscriptions/[0-9a-fA-F-]+/resourceGroups/[a-zA-Z0-9-_()]+/providers/Microsoft\.Storage/storageAccounts/[a-z0-9]+$`); !valid {
			g.err = fmt.Errorf("storage Account Resource ID variable validation failed with error: %s", err)
		}
		g.storageAccount.Resource = g.newStorageAccountResource()
		if g.storageAccount.Resource.Properties != nil {
			g.storageAccount.Uri = g.storageAccount.Resource.Properties.(map[string]interface{})["primaryEndpoints"].(map[string]interface{})["blob"].(string)
		} else {
			g.err = fmt.Errorf("storage account resource not found or is malformed")
		}
	}
	return g.storageAccount
}

func (g *GlobalVars) newStorageAccountResource() armresources.GenericResource {
	// Get storage account resource
	client, err := armresources.NewClient(g.getSubscriptionId(), g.getCred(), nil)
	if err != nil {
		g.err = fmt.Errorf("failed to create Azure resources client: %v", err)
	}

	// Get storage account resource
	getResourceResult, err := client.GetByID(context.Background(), g.storageAccount.Id, "2021-04-01", nil)
	// TODO: Set context with timeout and appropriate cancellation
	if err != nil {
		g.err = fmt.Errorf("failed to get storage account resource: %v", err)
	} else if *getResourceResult.GenericResource.Type != "Microsoft.Storage/storageAccounts" {
		g.err = fmt.Errorf("resource ID provided is not a storage account")
	}

	return getResourceResult.GenericResource
}

func (g *GlobalVars) getSubscriptionId() string {
	if g.subscriptionId == "" {
		g.subscriptionId = utils.GetRequiredString("raids.ABS.subscriptionId", nil)
		if valid, err := ValidateVariableValue(g.subscriptionId, `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`); !valid {
			g.err = fmt.Errorf("subscription ID variable validation failed with error: %s", err)
		}
	}
	return g.subscriptionId
}

func (g *GlobalVars) getArmMonitorClientFactory() *armmonitor.ClientFactory {
	if g.armMonitorClientFactory != nil {
		return g.armMonitorClientFactory
	}
	// Get a client factory for ARM monitor
	armMonitorClientFactory, err := armmonitor.NewClientFactory(g.getSubscriptionId(), g.getCred(), nil)
	if err != nil {
		g.err = fmt.Errorf("failed to create Azure monitor client factory: %v", err)
	}
	return armMonitorClientFactory
}

func (g *GlobalVars) getLogsClient() *azquery.LogsClient {
	if g.logsClient != nil {
		return g.logsClient
	}
	// Get a logs client
	logsClient, err := azquery.NewLogsClient(g.getCred(), nil)
	if err != nil {
		g.err = fmt.Errorf("failed to create Azure logs client: %v", err)
	}
	return logsClient
}
