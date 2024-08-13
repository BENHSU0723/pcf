package consumer

import (
	"context"
	"strings"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
)

// Create Subscription to UDR on subscription Data(including 5G VN Group)
func CreateSubscriptionDataSubscription(ue *pcf_context.UeContext) (
	subscriptionID string, problemDetails *models.ProblemDetails, err error) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return "", &problemDetail, nil
	}
	udrClient := util.GetNudrClient(ue.UdrUri)
	subscriptionDataSubscriptions := models.SubscriptionDataSubscriptions{
		UeId: ue.Supi,
		CallbackReference: pcf_context.GetSelf().GetIPv4Uri() +
			pcf_context.SubscriptionDataChangeNotifyUri + "/" +
			ue.Supi,
	}
	_, httpResp, localErr := udrClient.SubsToNofifyCollectionApi.PostSubscriptionDataSubscriptions(context.Background(), subscriptionDataSubscriptions)
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		subscriptionID := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		logger.ConsumerLog.Debugf("SubscriptionData Data Subscription ID: %s", subscriptionID)
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
func RemoveSubscriptionDataSubscription(ue *pcf_context.UeContext, subscriptionID string) (
	problemDetails *models.ProblemDetails, err error) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return &problemDetail, nil
	}
	udrClient := util.GetNudrClient(ue.UdrUri)
	httpResp, localErr := udrClient.SubsToNotifyDocumentApi.
		RemovesubscriptionDataSubscriptions(context.Background(), subscriptionID)
	if localErr == nil {
		logger.ConsumerLog.Debugf("Nudr_DataRepository Remove Subscription Data Subscription Status %s",
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
