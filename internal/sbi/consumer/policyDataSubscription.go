package consumer

import (
	"context"
	"strings"

	"github.com/antihax/optional"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

// Create Subscription to UDR on UE policy Data(including 5G VN Group)
func CreateUEPolicyDataSubscription(ue *pcf_context.UeContext) (
	subscriptionID string, problemDetails *models.ProblemDetails, err error) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return "", &problemDetail, nil
	}
	udrClient := util.GetNudrClient(ue.UdrUri)

	//TODO: add some element of MonitoredResourceUris
	logger.ConsumerLog.Debug("supi:", ue.Supi, " gpsi:", ue.Gpsi)
	optData := optional.NewInterface(models.PolicyDataSubscription{
		NotificationUri: pcf_context.GetSelf().GetIPv4Uri() +
			pcf_context.PolicyDataChangeNotifyUri + "/" +
			ue.Supi,
		MonitoredResourceUris: []string{"Here", "is", "Empty!!"},
	})
	postSubsOpts := Nudr_DataRepository.PolicyDataSubsToNotifyPostParamOpts{
		PolicyDataSubscription: optData,
	}
	_, httpResp, localErr := udrClient.DefaultApi.
		PolicyDataSubsToNotifyPost(context.Background(), &postSubsOpts)

	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		subscriptionID := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		logger.ConsumerLog.Debugf("Policy Data Subscription ID: %s", subscriptionID)
		return subscriptionID, nil, nil
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return "", problemDetails, err
}

// Delete Subscription to UDR on subscription Data(including 5G VN Group)
func RemovePolicyDataSubscription(ue *pcf_context.UeContext, subscriptionID string) (
	problemDetails *models.ProblemDetails, err error) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return &problemDetail, nil
	}
	udrClient := util.GetNudrClient(ue.UdrUri)
	httpResp, localErr := udrClient.DefaultApi.
		PolicyDataSubsToNotifySubsIdDelete(context.Background(), subscriptionID)
	if localErr == nil {
		logger.ConsumerLog.Debugf("Nudr_DataRepository Remove Policy Data Subscription Status %s",
			httpResp.Status)
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return
}
