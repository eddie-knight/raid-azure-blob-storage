package armory

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
	"github.com/privateerproj/privateer-sdk/raidengine"
	"github.com/privateerproj/privateer-sdk/utils"
)

// -----
// Strike and Movements for CCC_C04_TR01
// -----

// CCC_C04_TR01 conforms to the Strike function type
func (a *ABS) CCC_C04_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C04_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service logs all access attempts, including successful and failed login attempts.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C04",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C04_TR01_T01)

	if result.Movements["CCC_C04_TR01_T01"].Passed {
		raidengine.ExecuteMovement(&result, CCC_C04_TR01_T02)
		raidengine.ExecuteMovement(&result, CCC_C04_TR01_T03)
	}

	StrikeResultSetter(
		"All access attempts are logged",
		"Not all access attempts are logged, see movement results for more details",
		&result)

	return
}

func CCC_C04_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement tests that logging of access attempts is configured for the storage account",
		Function:    utils.CallerPath(0),
	}

	storageAccountBlobResourceId := globals.getStorageAccount().Id + "/blobServices/default"
	confirmLoggingToLogAnalyticsIsConfigured(storageAccountBlobResourceId, &result)
	return
}

func CCC_C04_TR01_T02() (result raidengine.MovementResult) {
	storageAccount := globals.getStorageAccount()
	result = raidengine.MovementResult{
		Description: "This movement tests that a successful login attempt is logged",
		Function:    utils.CallerPath(0),
	}

	token := globals.getToken(&result)
	response := MakeGETRequest(storageAccount.Uri, token, &result, nil, nil)

	if response.StatusCode != http.StatusOK {
		result.Passed = false
		result.Message = "Could not successfully authenticate with storage account"
		return
	}

	confirmHTTPResponseIsLogged(response, storageAccount.Id, globals.getLogsClient(), &result)
	return
}

func CCC_C04_TR01_T03() (result raidengine.MovementResult) {
	storageAccount := globals.getStorageAccount()
	result = raidengine.MovementResult{
		Description: "This movement tests that a failed login attempt is logged",
		Function:    utils.CallerPath(0),
	}

	response := MakeGETRequest(storageAccount.Uri, "", &result, nil, nil)

	if response.StatusCode != http.StatusUnauthorized {
		result.Passed = false
		result.Message = "Could not unsuccessfully authenticate with storage account"
		return
	}

	confirmHTTPResponseIsLogged(response, storageAccount.Id, globals.getLogsClient(), &result)
	return
}

func confirmHTTPResponseIsLogged(response *http.Response, resourceId string, logsClient *azquery.LogsClient, result *raidengine.MovementResult) {
	// Create a kusto query to find our request/response in the logs
	kustoQuery := fmt.Sprintf(
		"StorageBlobLogs | where StatusCode == %d and CorrelationId == '%s'",
		response.StatusCode,
		response.Header.Get("x-ms-request-id"))

	// Time might not be same on client vs server so add some buffer
	queryInterval := azquery.NewTimeInterval(time.Now().UTC().Add(-2*time.Minute), time.Now().UTC().Add(2*time.Minute))

	// There is a 2-5 minute ingestion delay, wait for 90 seconds...
	log.Default().Printf("Waiting 90 seconds for logs to be ingested")
	time.Sleep(90 * time.Second)

	// Then loop every 10 seconds until we have got to 5 minutes
	for i := 0; i <= 21; i++ {

		time.Sleep(10 * time.Second)

		logsResult, err := logsClient.QueryResource(
			context.Background(),
			resourceId,
			azquery.Body{
				Query:    to.Ptr(kustoQuery),
				Timespan: to.Ptr(queryInterval),
			},
			nil)

		if err != nil {
			result.Passed = false
			result.Message = fmt.Sprintf("Failed to query logs: %v", err)
			return
		}

		if logsResult.Error != nil {
			result.Passed = false
			result.Message = fmt.Sprintf("Error when querying logs: %v", logsResult.Error)
			return
		}

		if len(logsResult.Results.Tables) == 1 && len(logsResult.Results.Tables[0].Rows) > 0 {
			log.Default().Printf("Log result found after %d seconds", 90+(i*10))
			result.Passed = true
			result.Message = fmt.Sprintf("%d response from %v was logged", response.StatusCode, response.Request.URL.Host)
			return
		}

		log.Default().Printf("Log result not found after %d seconds", 90+(i*10))
	}

	result.Passed = false
	result.Message = fmt.Sprintf("%d response from %v was not logged", response.StatusCode, response.Request.URL)
}

func confirmLoggingToLogAnalyticsIsConfigured(resourceId string, result *raidengine.MovementResult) {
	armMonitorClientFactory := globals.getArmMonitorClientFactory()
	pager := armMonitorClientFactory.NewDiagnosticSettingsClient().NewListPager(resourceId, nil)

	for pager.More() {
		page, err := pager.NextPage(context.Background())

		if err != nil {
			result.Passed = false
			result.Message = fmt.Sprintf("Could not find diagnostic setting: %v", err)
			return
		}

		for _, v := range page.Value {
			if *v.Type == "Microsoft.Insights/diagnosticSettings" && *v.Properties.WorkspaceID != "" {

				readLogged := false
				writeLogged := false
				deleteLogged := false

				for _, logSetting := range v.Properties.Logs {
					if *logSetting.Enabled {
						if logSetting.CategoryGroup != nil {
							switch *logSetting.CategoryGroup {
							case "audit", "allLogs":
								readLogged = true
								writeLogged = true
								deleteLogged = true
							}
						} else if logSetting.Category != nil {
							switch *logSetting.Category {
							case "StorageRead":
								readLogged = true
							case "StorageWrite":
								writeLogged = true
							case "StorageDelete":
								deleteLogged = true
							}
						}
					}
				}

				if readLogged && writeLogged && deleteLogged {
					result.Passed = true

					// Try to extract the name of the log analytics workspace
					logAnalyticsWorkspaceName := *v.Properties.WorkspaceID
					match := regexp.MustCompile("^/subscriptions/[0-9a-z-]{36}/resourceGroups/.+?/providers/Microsoft.OperationalInsights/workspaces/(.*?)$").FindStringSubmatch(logAnalyticsWorkspaceName)

					if len(match) > 0 {
						logAnalyticsWorkspaceName = match[1]
					}

					result.Message = fmt.Sprintf("Storage account is configured to emit to log analytics workspace %s", logAnalyticsWorkspaceName)
					return
				}
			}
		}
	}

	result.Passed = false
	result.Message = "Storage account is not configured to emit to log analytics workspace destination"
}
