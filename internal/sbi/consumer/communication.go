package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/pcf/pkg/factory"
)

func AmfStatusChangeSubscribe(amfUri string, guamiList []models.Guami) (
	problemDetails *models.ProblemDetails, err error,
) {
	logger.ConsumerLog.Debugf("PCF Subscribe to AMF status[%+v]", amfUri)
	pcfSelf := pcf_context.GetSelf()
	client := util.GetNamfClient(amfUri)

	subscriptionData := models.SubscriptionData{
		AmfStatusUri: fmt.Sprintf("%s"+factory.PcfCallbackResUriPrefix+"/amfstatus", pcfSelf.GetIPv4Uri()),
		GuamiList:    guamiList,
	}
	ctx, pd, err := pcf_context.GetSelf().GetTokenCtx(models.ServiceName_NAMF_COMM, models.NfType_AMF)
	if err != nil {
		return pd, err
	}
	res, httpResp, localErr := client.SubscriptionsCollectionDocumentApi.AMFStatusChangeSubscribe(
		ctx, subscriptionData)
	defer func() {
		if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
			logger.ConsumerLog.Errorf("AMFStatusChangeSubscribe response body cannot close: %+v",
				rspCloseErr)
		}
	}()
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		logger.ConsumerLog.Debugf("location header: %+v", locationHeader)

		subscriptionID := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		amfStatusSubsData := pcf_context.AMFStatusSubscriptionData{
			AmfUri:       amfUri,
			AmfStatusUri: res.AmfStatusUri,
			GuamiList:    res.GuamiList,
		}
		pcfSelf.NewAmfStatusSubscription(subscriptionID, amfStatusSubsData)
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return nil, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("%s: server no response", amfUri)
	}
	return problemDetails, err
}

// Request to AMF that Subscribe to notifications of N1 message for UE Policy Delivery Resul
func N1N2MessageSubscibe(policyAssociationRequest models.PolicyAssociationRequest) error {
	pcfSelf := pcf_context.GetSelf()
	amfUri := SendNFInstancesAMF(pcfSelf.NrfUri, *policyAssociationRequest.Guami, models.ServiceName_NAMF_COMM)
	if amfUri == "" {
		// TODO: fix the problem of empty response from SendNFInstancesAMF(), It usually happens.
		amfUri = "http://127.0.0.18:8000"
	}
	logger.UEpolicylog.Warnln("N1N2MessageSubscibe  amfuri: ", amfUri)
	client := util.GetNamfClient(amfUri)

	//TODO: not sure the element here is correct
	var ueN1N2InfoSubscriptionCreateData = models.UeN1N2InfoSubscriptionCreateData{
		N1MessageClass: models.N1MessageClass_UPDP, //indicate subscribing the UE policy related n1 msg
		N1NotifyCallbackUri: pcfSelf.GetIPv4Uri() +
			pcf_context.N1UePolicyDataNotifyUri + "/" +
			policyAssociationRequest.Supi,
	}
	logger.UEpolicylog.Warn(ueN1N2InfoSubscriptionCreateData)
	ueN1N2InfoSubscriptionCreatedData, rsp, err :=
		client.N1N2SubscriptionsCollectionForIndividualUEContextsDocumentApi.N1N2MessageSubscribe(context.Background(), policyAssociationRequest.Supi, ueN1N2InfoSubscriptionCreateData)
	if err != nil {
		err = fmt.Errorf(fmt.Sprintf("N1N2MessageSubscibe error: %s", err.Error()))
		logger.UEpolicylog.Errorln(err.Error())
		return err
	} else if rsp.StatusCode != http.StatusCreated {
		err = fmt.Errorf(fmt.Sprintf("N1N2MessageSubscibe fail, status code:%d", rsp.StatusCode))
		logger.UEpolicylog.Errorln(err.Error())
		return err
	} else {
		logger.UEpolicylog.Info("N1N2MessageSubscibe success!!")
		uecontext := pcfSelf.PCFUeFindBySUPI(policyAssociationRequest.Supi)
		uecontext.N1N2InfoSubscriptionCreatedData = &ueN1N2InfoSubscriptionCreatedData
	}
	return nil
}

// PCF sends the UE policy to the UE via the AMF by invoking the Namf_Communication_N1N2MessageTransfer service operation
func N1N2MessageTransfer(n1msgContainer []uint8, policyAssociationRequest models.PolicyAssociationRequest) error {
	pcfSelf := pcf_context.GetSelf()
	amfUri := SendNFInstancesAMF(pcfSelf.NrfUri, *policyAssociationRequest.Guami, models.ServiceName_NAMF_COMM)
	if amfUri == "" {
		// TODO: fix the problem of empty response from SendNFInstancesAMF(), It usually happens.
		amfUri = "http://127.0.0.18:8000"
	}
	logger.UEpolicylog.Warnln("N1N2MessageTransfer  amfuri: ", amfUri)
	client := util.GetNamfClient(amfUri)

	//TODO: not sure the element here is correct
	var ueN1N2MessageTransferRequest = models.N1N2MessageTransferRequest{
		JsonData: &models.N1N2MessageTransferReqData{
			N1MessageContainer: &models.N1MessageContainer{
				N1MessageClass: models.N1MessageClass_UPDP, //UE Policy Delivery
				N1MessageContent: &models.RefToBinaryData{
					ContentId: "MANAGE_UE_POLICY_COMMAND", //TODO: not sure ContentId value is for what
				},
			},
			SupportedFeatures: "5GLAN-service",
		},
		BinaryDataN1Message: n1msgContainer,
	}
	logger.UEpolicylog.Warnln("SUPI: ", policyAssociationRequest.Supi, ", GPSI: ", policyAssociationRequest.Gpsi)
	ueN1N2MessageTransferRspData, rsp, err :=
		client.N1N2MessageCollectionDocumentApi.N1N2MessageTransfer(context.Background(), policyAssociationRequest.Supi, ueN1N2MessageTransferRequest)
	if err != nil {
		err = fmt.Errorf(fmt.Sprintf("N1N2MessageTransfer error:%s", err.Error()))
		logger.UEpolicylog.Errorln(err.Error())
		return err
	} else if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusAccepted {
		err = fmt.Errorf(fmt.Sprintf("N1N2MessageTransfer fail, status code:%d", rsp.StatusCode))
		logger.UEpolicylog.Errorln(err.Error())
		return err
	} else {
		logger.UEpolicylog.Info("N1N2MessageTransfer success!!")
		logger.UEpolicylog.Info(ueN1N2MessageTransferRspData)
	}
	return nil
}
