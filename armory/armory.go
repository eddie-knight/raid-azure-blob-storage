package armory

import (
	"crypto/tls"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	hclog "github.com/hashicorp/go-hclog"

	"github.com/privateerproj/privateer-sdk/raidengine"
	"github.com/privateerproj/privateer-sdk/utils"
)

// Conforms to the Armory interface type
type ABS struct {
	Tactics map[string][]raidengine.Strike     // Required, allows you to sort which strikes are run for each control
	Log     hclog.Logger                       // Recommended, allows you to set the log level for each log message
	Results map[string]raidengine.StrikeResult // Optional, allows cross referencing between strikes
}

type StorageAccount struct {
	Id       string
	Uri      string
	Resource armresources.GenericResource
}

type GlobalVars struct {
	storageAccount          StorageAccount
	subscriptionId          string
	token                   azcore.AccessToken
	cred                    *azidentity.DefaultAzureCredential
	logsClient              *azquery.LogsClient
	armMonitorClientFactory *armmonitor.ClientFactory
	err                     error
}

var globals GlobalVars

func (a *ABS) SetLogger(loggerName string) hclog.Logger {
	a.Log = raidengine.GetLogger(loggerName, false)
	return a.Log
}

func (a *ABS) GetTactics() map[string][]raidengine.Strike {
	return a.Tactics
}

// Initialize is the first thing to run after the plugin's logger is set
func (a *ABS) Initialize() error {
	if globals.err != nil {
		return globals.err
	}
	return nil
}

func StrikeResultSetter(successMessage string, failureMessage string, result *raidengine.StrikeResult) {

	// If any movement fails, set strike result to failed
	for _, movementResult := range result.Movements {
		if !movementResult.Passed {
			result.Passed = false
			result.Message = failureMessage
			return
		}
	}

	// If no movements failed, set strike result to passed
	result.Passed = true
	result.Message = successMessage
}

// -----
// Strike and Movements for CCC_C01_TR01
// -----

// CCC_C01_TR01 conforms to the Strike function type
func (a *ABS) CCC_C01_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C01_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service enforces the use of secure transport protocols for all network communications (e.g., TLS 1.2 or higher).",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C01",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C01_TR01_T01)

	StrikeResultSetter("Default TLS version is TLS 1.2 or TLS 1.3",
		"Default TLS version is not TLS 1.2 or TLS 1.3, see movement results for more details",
		&result)

	return
}

// CCC_C01_TR01_T01 - Ensure GET requests communicate via TLS 1.2 or higher
func CCC_C01_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "Default TLS version is TLS 1.2 or TLS 1.3",
		Function:    utils.CallerPath(0),
	}

	// Get access token
	token := globals.getToken(&result)
	if token == "" {
		return
	}

	// Check TLS version of response
	CheckTLSVersion(globals.getStorageAccount().Uri, token, &result)
	if !result.Passed {
		return
	}
	return
}

// -----
// Strike and Movements for CCC_C01_TR02
// -----

// CCC_C01_TR02 conforms to the Strike function type
func (a *ABS) CCC_C01_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C01_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service automatically redirects incoming unencrypted HTTP requests to HTTPS.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C01",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C01_TR02_T01)

	StrikeResultSetter("HTTP requests are not supported",
		"HTTP requests are supported, see movement results for more details",
		&result)

	return
}

func CCC_C01_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "HTTP requests are not supported",
		Function:    utils.CallerPath(0),
	}

	ConfirmHTTPRequestFails(globals.getStorageAccount().Uri, &result)

	return
}

// -----
// Strike and Movements for CCC_C01_TR03
// -----

// CCC_C01_TR03 conforms to the Strike function type
func (a *ABS) CCC_C01_TR03() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C01_TR03"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service rejects or blocks any attempts to establish outgoing connections using outdated or insecure protocols (e.g., SSL, TLS 1.0, or TLS 1.1).",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C01",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C01_TR03_T01)
	raidengine.ExecuteMovement(&result, CCC_C01_TR03_T02)

	StrikeResultSetter("All insecure TLS versions are not supported",
		"One or more insecure TLS versions are supported, see movement results for more details",
		&result)

	return
}

func CCC_C01_TR03_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "TLS Version 1.0 is not supported",
		Function:    utils.CallerPath(0),
	}

	tlsVersion := tls.VersionTLS10

	ConfirmOutdatedProtocolRequestsFail(globals.getStorageAccount().Uri, &result, tlsVersion)
	return
}

func CCC_C01_TR03_T02() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "TLS Version 1.1 is not supported",
		Function:    utils.CallerPath(0),
	}

	tlsVersion := tls.VersionTLS11

	ConfirmOutdatedProtocolRequestsFail(globals.getStorageAccount().Uri, &result, tlsVersion)
	return
}

// -----
// Strike and Movements for CCC_C02_TR01
// -----

// CCC_C02_TR01 conforms to the Strike function type
func (a *ABS) CCC_C02_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C02_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service encrypts all stored data at rest using industry-standard encryption algorithms (e.g., AES-256).",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C02",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C02_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C02_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C02_TR01
	return
}

// -----
// Strike and Movements for CCC_C02_TR02
// -----

// CCC_C02_TR02 conforms to the Strike function type
func (a *ABS) CCC_C02_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C02_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Admin users can verify and audit encryption status for stored data at rest, including verification of key management processes.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C02",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C02_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C02_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C02_TR02
	return
}

// -----
// Strike and Movements for CCC_C03_TR01
// -----

// CCC_C03_TR01 conforms to the Strike function type
func (a *ABS) CCC_C03_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C03_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Ensure that MFA is required for all user access to the service interface.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C03",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C03_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C03_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C03_TR01
	return
}

// -----
// Strike and Movements for CCC_C03_TR02
// -----

// CCC_C03_TR02 conforms to the Strike function type
func (a *ABS) CCC_C03_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C03_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Ensure that MFA is required for all administrative access to the management interface.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C03",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C03_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C03_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C03_TR02
	return
}

// -----
// Strike and Movements for CCC_C04_TR02
// -----

// CCC_C04_TR02 conforms to the Strike function type
func (a *ABS) CCC_C04_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C04_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service logs all changes to configuration, including administrative actions and modifications to user roles or privileges.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C04",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C04_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C04_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C04_TR02
	return
}

// -----
// Strike and Movements for CCC_C05_TR01
// -----

// CCC_C05_TR01 conforms to the Strike function type
func (a *ABS) CCC_C05_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C05_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service blocks access to sensitive resources and admin access from untrusted sources, including unauthorized IP addresses, domains, or networks that are not included in a pre-approved allowlist.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C05",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C05_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C05_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C05_TR01
	return
}

// -----
// Strike and Movements for CCC_C05_TR02
// -----

// CCC_C05_TR02 conforms to the Strike function type
func (a *ABS) CCC_C05_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C05_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service logs all access attempts from untrusted entities, including failed connection attempts.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C05",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C05_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C05_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C05_TR02
	return
}

// -----
// Strike and Movements for CCC_C05_TR04
// -----

// CCC_C05_TR04 conforms to the Strike function type
func (a *ABS) CCC_C05_TR04() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C05_TR04"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service prevents unauthorized cross-tenant access, ensuring that only allowlisted services from other tenants can access resources.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C05",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C05_TR04_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C05_TR04_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C05_TR04
	return
}

// -----
// Strike and Movements for CCC_C06_TR01
// -----

// CCC_C06_TR01 conforms to the Strike function type
func (a *ABS) CCC_C06_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C06_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service prevents deployment in restricted regions or cloud availability zones, blocking any provisioning attempts in designated areas.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C06",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C06_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C06_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C06_TR01
	return
}

// -----
// Strike and Movements for CCC_C06_TR02
// -----

// CCC_C06_TR02 conforms to the Strike function type
func (a *ABS) CCC_C06_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C06_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service ensures that replication of data, backups, and disaster recovery operations do not occur in restricted regions or availability zones.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C06",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C06_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C06_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C06_TR02
	return
}

// -----
// Strike and Movements for CCC_C07_TR01
// -----

// CCC_C07_TR01 conforms to the Strike function type
func (a *ABS) CCC_C07_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C07_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service generates real-time alerts whenever non-human entities (e.g., automated scripts or processes) attempt to enumerate resources or services.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C07",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C07_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C07_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C07_TR01
	return
}

// -----
// Strike and Movements for CCC_C07_TR02
// -----

// CCC_C07_TR02 conforms to the Strike function type
func (a *ABS) CCC_C07_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C07_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Confirm that logs are properly generated and accessible for review following non-human enumeration attempts.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C07",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C07_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C07_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C07_TR02
	return
}

// -----
// Strike and Movements for CCC_C08_TR01
// -----

// CCC_C08_TR01 conforms to the Strike function type
func (a *ABS) CCC_C08_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_C08_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Data is replicated across multiple availability zones or regions.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C08",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_C08_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_C08_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_C08_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C08_TR02
// -----

// CCC_ObjStor_C08_TR02 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C08_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C08_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Admin users can verify the replication status of data across multiple zones or regions, including the replication locations and data synchronization status.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.C08",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C08_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C08_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C08_TR02
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C01_TR01
// -----

// CCC_ObjStor_C01_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C01_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C01_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "The service prevents access to any object storage bucket or object  that uses KMS keys not listed as trusted by the organization.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C01",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C01_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C01_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C01_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C02_TR01
// -----

// CCC_ObjStor_C02_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C02_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C02_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Admin users can configure bucket-level permissions uniformly across  all buckets, ensuring that object-level permissions cannot be  applied without explicit authorization.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C02",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C02_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C02_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C02_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C03_TR01
// -----

// CCC_ObjStor_C03_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C03_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C03_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Object storage buckets cannot be deleted after creation.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C03",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C03_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C03_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C03_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C03_TR02
// -----

// CCC_ObjStor_C03_TR02 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C03_TR02() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C03_TR02"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Retention policy for object storage buckets cannot be unset.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C03",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C03_TR02_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C03_TR02_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C03_TR02
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C05_TR01
// -----

// CCC_ObjStor_C05_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C05_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C05_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "All objects stored in the object storage system automatically receive  a default retention policy that prevents premature deletion or  modification.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C05",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C05_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C05_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C05_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C05_TR04
// -----

// CCC_ObjStor_C05_TR04 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C05_TR04() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C05_TR04"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Attempts to delete or modify objects that are subject to an active  retention policy are prevented.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C05",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C05_TR04_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C05_TR04_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C05_TR04
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C06_TR01
// -----

// CCC_ObjStor_C06_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C06_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C06_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Verify that when two objects with the same name are uploaded to the  bucket, the object with the same name is not overwritten and that  both objects are stored with unique identifiers.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C06",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C06_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C06_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C06_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C06_TR04
// -----

// CCC_ObjStor_C06_TR04 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C06_TR04() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C06_TR04"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Previous versions of an object can be accessed and restored after  an object is modified or deleted.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C06",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C06_TR04_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C06_TR04_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C06_TR04
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C07_TR01
// -----

// CCC_ObjStor_C07_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C07_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C07_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Access logs for all object storage buckets are stored in a separate  bucket.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.C07",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C07_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C07_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C07_TR01
	return
}

// -----
// Strike and Movements for CCC_ObjStor_C08_TR01
// -----

// CCC_ObjStor_C08_TR01 conforms to the Strike function type
func (a *ABS) CCC_ObjStor_C08_TR01() (strikeName string, result raidengine.StrikeResult) {
	// set default return values
	strikeName = "CCC_ObjStor_C08_TR01"
	result = raidengine.StrikeResult{
		Passed:      false,
		Description: "Object replication to destinations outside of the defined trust  perimeter is automatically blocked, preventing replication to  untrusted resources.",
		Message:     "Strike has not yet started.", // This message will be overwritten by subsequent movements
		DocsURL:     "https://maintainer.com/docs/raids/ABS",
		ControlID:   "CCC.ObjStor.08",
		Movements:   make(map[string]raidengine.MovementResult),
	}

	raidengine.ExecuteMovement(&result, CCC_ObjStor_C08_TR01_T01)
	// TODO: Additional movement calls go here

	return
}

func CCC_ObjStor_C08_TR01_T01() (result raidengine.MovementResult) {
	result = raidengine.MovementResult{
		Description: "This movement is still under construction",
		Function:    utils.CallerPath(0),
	}

	// TODO: Use this section to write a single step or test that contributes to CCC_ObjStor_C08_TR01
	return
}
