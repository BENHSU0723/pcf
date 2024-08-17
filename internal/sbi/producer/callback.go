package producer

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/BENHSU0723/nas_public/uePolicyContainer"
	"github.com/BENHSU0723/openapi_public/Nudr_DataRepository"
	"github.com/antihax/optional"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
)

func HandleAmfStatusChangeNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")

	notification := request.Body.(models.AmfStatusChangeNotification)

	AmfStatusChangeNotifyProcedure(notification)

	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// TODO: handle AMF Status Change Notify
func AmfStatusChangeNotifyProcedure(notification models.AmfStatusChangeNotification) {
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", notification)
}

// handle UDR policy data changed
func HandleUdrPolicyDataChangeNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Policy Data Change Notify is not implemented.")

	notification := request.Body.(models.PolicyDataChangeNotification)
	supi := request.Params["supi"]

	UdrPolicyDataChangeNotifyProcedure(supi, notification)

	return httpwrapper.NewResponse(http.StatusNotImplemented, nil, nil)
}

// TODO: handle udr Policy Data Change Notify
func UdrPolicyDataChangeNotifyProcedure(supi string, notification models.PolicyDataChangeNotification) {
}

func HandleInfluenceDataUpdateNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Infof("[PCF] Handle Influence Data Update Notify")

	notifications := request.Body.([]models.TrafficInfluDataNotif)
	supi := request.Params["supi"]
	pduSessionId := request.Params["pduSessionId"]

	if problemDetails := InfluenceDataUpdateNotifyProcedure(supi, pduSessionId, notifications); problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func InfluenceDataUpdateNotifyProcedure(supi, pduSessionId string,
	notifications []models.TrafficInfluDataNotif,
) *models.ProblemDetails {
	smPolicyID := fmt.Sprintf("%s-%s", supi, pduSessionId)
	ue := pcf_context.GetSelf().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.CallbackLog.Errorf(problemDetail.Detail)
		return &problemDetail
	}
	smPolicy := ue.SmPolicyData[smPolicyID]
	decision := smPolicy.PolicyDecision
	influenceDataToPccRule := smPolicy.InfluenceDataToPccRule
	precedence := getAvailablePrecedence(smPolicy.PolicyDecision.PccRules)
	for _, notification := range notifications {
		influenceID := getInfluenceID(notification.ResUri)
		if influenceID == "" {
			continue
		}
		// notifying deletion
		if notification.TrafficInfluData == nil {
			pccRuleID := influenceDataToPccRule[influenceID]
			decision = &models.SmPolicyDecision{}
			if err := smPolicy.RemovePccRule(pccRuleID, decision); err != nil {
				logger.CallbackLog.Errorf("Remove PCC rule error: %+v", err)
			}
			delete(influenceDataToPccRule, influenceID)
		} else {
			trafficInfluData := *notification.TrafficInfluData
			if pccRuleID, ok := influenceDataToPccRule[influenceID]; ok {
				// notifying Individual Influence Data update
				pccRule := decision.PccRules[pccRuleID]
				util.SetSmPolicyDecisionByTrafficInfluData(decision, pccRule, trafficInfluData)
			} else {
				// notifying Individual Influence Data creation

				pccRule := util.CreatePccRule(smPolicy.PccRuleIdGenerator, precedence, nil, trafficInfluData.AfAppId)
				util.SetSmPolicyDecisionByTrafficInfluData(decision, pccRule, trafficInfluData)
				influenceDataToPccRule[influenceID] = pccRule.PccRuleId
				smPolicy.PccRuleIdGenerator++
				if precedence < Precedence_Maximum {
					precedence++
				}
			}
		}
	}
	smPolicyNotification := models.SmPolicyNotification{
		ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
		SmPolicyDecision: decision,
	}
	go SendSMPolicyUpdateNotification(smPolicy.PolicyContext.NotificationUri, &smPolicyNotification)
	return nil
}

func getInfluenceID(resUri string) string {
	temp := strings.Split(resUri, "/")
	return temp[len(temp)-1]
}

func HandleUdrSubscriptionDataChangeNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Info("[PCF] Handle Udr SubscriptionData Change Notify")

	notification := request.Body.(models.DataChangeNotify)
	supi := request.Params["supi"]

	if problemDetails := UdrSubscriptionDataChangeNotifyProcedure(supi, notification); problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}

}

// TODO: handle Subscription Data(including 5G VN Group) Change Notify
// this procedure need to do POLICY_DECISION and decide whether to send N1N2 policy procedure to AMF
func UdrSubscriptionDataChangeNotifyProcedure(supi string, notification models.DataChangeNotify) *models.ProblemDetails {
	logger.CallbackLog.Infof("Receive Subscription Data change notification[%+v]", notification)

	ue := pcf_context.GetSelf().PCFUeFindBySUPI(supi)
	if ue == nil {
		problemDetail := util.GetProblemDetail("SUPI not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.CallbackLog.Errorf(problemDetail.Detail)
		return &problemDetail
	}

	//TODO: deal with the subscription Data(including 5G VN Group) modify
	logger.CallbackLog.Warnln("No reaction when receive subs data notify!!")
	return nil
}

func HandleAmfUePolicyDeliveryNotify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CallbackLog.Warnln("Handle AMF UE_Policy_Delivery Notify, contains the UE policy container from UE")

	notification := request.Body.(models.N1MessageNotify)
	supi := request.Params["supi"]

	if problemDetails := AmfUePolicyDeliveryNotifyProcedure(supi, notification); problemDetails != nil {
		//  On failure or redirection, one of the HTTP status code listed in
		// Table 6.1.5.4.3.1-3 shall be returned(TS 29.518 V17.9.0)
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		// On success, "204 No Content" shall be returned and the payload body of the POST response shall be empty.
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func AmfUePolicyDeliveryNotifyProcedure(supi string, n1msgNotify models.N1MessageNotify) *models.ProblemDetails {
	// step 15~18 of : UE Policy Association Establishment procedure - Non-roaming,TS 29.513 V17.10.0, Figure 5.6.1.2-1
	logger.CallbackLog.Warnln("[AmfUePolicyDeliveryNotifyProcedure] supi: ", supi)

	// find ue context
	pcfSelf := pcf_context.GetSelf()
	var ue *pcf_context.UeContext
	if val, ok := pcfSelf.UePool.Load(supi); ok {
		ue = val.(*pcf_context.UeContext)
	} else {
		err := fmt.Errorf("There is no SUPI[%v] ue context in PCF", supi)
		logger.CallbackLog.Errorln(err.Error())
		return &models.ProblemDetails{
			Title:  "Search UE context error",
			Status: http.StatusNotFound,
			Detail: err.Error(),
		}
	}
	// stop the timer T3501 for retransmit [manage ue policy service]
	ue.StopT3501()

	// process the n1 notify msg case by case
	switch msgType := n1msgNotify.JsonData.N1MessageContainer.N1MessageClass; msgType {
	case models.N1MessageClass_UPDP:
		// decode the ue policy container
		uePolContainer := uePolicyContainer.NewUePolDeliverySer()
		uePolContainer.UePolDeliverySerDecode(n1msgNotify.BinaryDataN1Message)

		switch uePolType := uePolContainer.GetHeaderMessageType(); uePolType {
		case uePolicyContainer.MsgTypeManageUEPolicyComplete:
			logger.CallbackLog.Warnln("enter [uePolicyContainer.MsgTypeManageUEPolicyComplete]")
			mngUePolComplete := uePolContainer.ManageUEPolicyComplete
			for polAssId, uePolData := range ue.UePolicyData {
				logger.CallbackLog.Warnf("=====ue context policy data=====, complete PTI:%v, uePolData.PTI:%v\n", mngUePolComplete.GetPTI(), uePolData.PTI)
				if uePolData.PTI == mngUePolComplete.GetPTI() {
					err := storeUePolicyToUdr(polAssId, supi, *uePolData, ue)
					if err != nil {
						logger.CallbackLog.Errorln("[storeUePolicyToUdr] err:", err.Error())
						return &models.ProblemDetails{
							Title:  "Store Ue Policy To UDR error",
							Status: http.StatusInternalServerError,
							Detail: err.Error(),
						}
					}
					break
				}
			}
		case uePolicyContainer.MsgTypeManageUEPolicyReject:
			logger.CallbackLog.Errorln("enter [uePolicyContainer.MsgTypeManageUEPolicyReject]")
			// TODO
		}
	default:
		logger.CallbackLog.Errorf("N1 Msg Notify Class[%v] is not handled yet!!\n", msgType)
	}
	logger.CallbackLog.Warnln("PCF handle AmfUePolicyDeliveryNotifyProcedure successfully!!!")

	return nil
}

func storeUePolicyToUdr(polAssId, supi string, uePolData pcf_context.UeUePolicyData, ue *pcf_context.UeContext) error {
	if ue.UdrUri != "" {
		logger.CallbackLog.Warnln("UdrUri: ", ue.UdrUri)
		client := util.GetBenNudrClient(ue.UdrUri)
		uePolSet, err := util.UePolicyContentToModelUePolicySection(uePolData.UePolicyContainerListContent, uePolData.UrspRuleSet)
		if err != nil {
			return err
		}
		logger.CallbackLog.Warnf("uePolSet: %+v\n", uePolSet)
		StoredData := Nudr_DataRepository.PolicyDataUesUeIdUePolicySetPutParamOpts{UePolicySet: optional.NewInterface(*uePolSet)}
		logger.CallbackLog.Warnf("StoredData to udr:%+v\n", StoredData)

		ctx, _, err1 := pcf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
		if err1 != nil {
			return err1
		}

		response, err := client.DefaultApi.PolicyDataUesUeIdUePolicySetPut(ctx, supi, &StoredData)
		if err != nil {
			if response != nil && (*response).StatusCode == http.StatusNotFound {
				logger.CallbackLog.Warnf("Can't find UE[%s] UE Policy Data in UDR", ue.Supi)
				return fmt.Errorf(" PCF can't find UE[%s] UE Policy Data in UDR", ue.Supi)
			} else {
				logger.CallbackLog.Errorf("PolicyDataUesUeIdUePolicySetPut: %+v", err.Error())
				return fmt.Errorf("error happen when Send Put request To UDR:%v", err)
			}
		}

	}
	return nil
}
