package producer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BENHSU0723/nas_public/uePolicyContainer"
	ben_models "github.com/BENHSU0723/openapi_public/models"
	"github.com/free5gc/openapi/models"
	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/consumer"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
	"github.com/mohae/deepcopy"
)

// Create UE Policy - Handle the UE policy creation request from NF(eg. AMf)
func HandlePostUePolicyRequest(request *httpwrapper.Request) *httpwrapper.Response {

	// step 1: log
	logger.UEpolicylog.Info("Handle HandlePostUePolicyRequest")

	// step 2: retrieve request
	polAssoId := request.Params["polAssoId"]
	requestDataType := request.Body.(models.PolicyAssociationRequest)

	// step 3: handle the message
	header, response, problemDetails := CreateUePolicyProcedure(polAssoId, requestDataType)
	logger.UEpolicylog.Debug(response)

	// step 4: process the return value from step 3
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}

}
func CreateUePolicyProcedure(polAssoId string,
	policyAssociationRequest models.PolicyAssociationRequest) (http.Header, *models.PolicyAssociation, *models.ProblemDetails) {
	//ref: 3GPP TS29.513-v17.10.0 section 5.6.1.2(Non-roaming)UE Policy Association Establishment

	//step 1: log and retrive ue data from PCFcontext.uePool
	logger.UEpolicylog.Infof("Handle HandlePostUePolicies")

	var response models.PolicyAssociation
	pcfSelf := pcf_context.GetSelf()
	var ue *pcf_context.UeContext
	if val, ok := pcfSelf.UePool.Load(policyAssociationRequest.Supi); ok {
		ue = val.(*pcf_context.UeContext)
	}
	if ue == nil {
		if newUe, err := pcfSelf.NewPCFUe(policyAssociationRequest.Supi); err != nil {
			// supi format dose not match "imsi-..."
			problemDetail := util.GetProblemDetail("Supi Format Error", util.ERROR_REQUEST_PARAMETERS)
			logger.UEpolicylog.Errorln(err.Error())
			return nil, nil, &problemDetail
		} else {
			ue = newUe
		}
	}

	//step 2. 3. : Query to UDR to GET the "UEPolicySet" resource by invoking Nudr_DataRepository_Query
	udrUri := getUdrUri(ue)
	if udrUri == "" {
		// Can't find any UDR support this Ue
		pcfSelf.UePool.Delete(ue.Supi)
		problemDetail := util.GetProblemDetail("Ue is not supported in PCF", util.USER_UNKNOWN)
		logger.UEpolicylog.Errorf("Ue[%s] is not supported in PCF", ue.Supi)
		return nil, nil, &problemDetail
	}
	ue.UdrUri = udrUri

	// logger.UEpolicylog.Warn("policy assoReq:", policyAssociationRequest)
	response.Request = deepcopy.Copy(&policyAssociationRequest).(*models.PolicyAssociationRequest)
	assolId := fmt.Sprintf("%s-%d", ue.Supi, ue.PolAssociationIDGenerator)
	uePolicy := ue.UePolicyData[assolId]

	if uePolicy == nil {
		client := util.GetBenNudrClient(udrUri)
		uePolicyData, response, err := client.DefaultApi.PolicyDataUesUeIdUePolicySetGet(context.Background(), ue.Supi)
		if err != nil { // || response == nil || response.StatusCode != http.StatusOK
			if response.StatusCode == http.StatusNotFound {
				logger.UEpolicylog.Warnf("Can't find UE[%s] UE Policy Data in UDR", ue.Supi)
			} else {
				problemDetail := util.GetProblemDetail(err.Error(), util.USER_UNKNOWN)
				logger.UEpolicylog.Errorf("PolicyDataUesUeIdUePolicySetGet: %+v", err.Error())
				return nil, nil, &problemDetail
			}
		}
		defer func() {
			if rspCloseErr := response.Body.Close(); rspCloseErr != nil {
				logger.UEpolicylog.Errorf("PolicyDataUesUeIdUePolicySetGet response cannot close: %+v", rspCloseErr)
			}
		}()
		if uePolicyData.UePolicySections != nil {
			uePolicy = ue.NewUePolicyData(assolId, policyAssociationRequest)
			uePolicy.UePolicySet = &uePolicyData
			ue.PolAssociationIDGenerator++
		}
	}
	// Create location header for update, delete, get
	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_UE_POLICY_CONTROL, assolId)
	logger.UEpolicylog.Tracef("UEPolicy association Id[%s] Create", assolId)
	logger.UEpolicylog.Warnf("internal group ids: [%+v]", policyAssociationRequest.GroupIds)

	// step 2. 3. : Additionally: Query to UDR to retrive 5GLAN VN group configuration by sending HTTP GET request to the "5GVnGroupsInternal"
	client := util.GetBenNudrClient(udrUri)
	intGroupIds := ben_models.InternalGroupIdList{Internalgroupids: policyAssociationRequest.GroupIds}
	vnGroupConfigs, rsp, err := client.Vn5gGroupsInternalDocumentApi.VN5GLANgroupDataOnInternalGroupIdsGet(context.Background(), intGroupIds)
	if err != nil || rsp == nil || rsp.StatusCode != http.StatusOK {
		problemDetail := util.GetProblemDetail("Can't find UE Group Configs set using Internal Group Ids in UDR", err.Error())
		logger.UEpolicylog.Errorln("Can't find UE Group Configs set using Internal Group Ids", policyAssociationRequest.GroupIds, " in UDR")
		return nil, nil, &problemDetail
	}
	defer func() {
		if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
			logger.UEpolicylog.Errorf("VN5GLANgroupDataOnInternalGroupIdsGet response cannot close: %+v", rspCloseErr)
		}
	}()
	logger.UEpolicylog.Warnln("Query group configs: ", vnGroupConfigs)

	//step 4. 5. : subscribe to UE policy data in UDR
	subsUEPolicyDataId, problemDetail, err := consumer.CreateUEPolicyDataSubscription(ue)
	if problemDetail != nil {
		logger.UEpolicylog.Errorf("Subscribe UDR Policy Data Failed Problem[%+v]", problemDetail)
	} else if err != nil {
		logger.UEpolicylog.Errorf("Subscribe UDR Policy Data Error[%v]", err.Error())
	}

	//step 4. 5. : Additionally, subscribe to 5G VN group configuration data in UDR
	subsSubscriptionDataId, problemDetail, err := consumer.CreateSubscriptionDataSubscription(ue)
	if problemDetail != nil {
		logger.UEpolicylog.Errorf("Subscribe UDR UE subscription Data(including 5G VN Group) Failed Problem[%+v]", problemDetail)
	} else if err != nil {
		logger.UEpolicylog.Errorf("Subscribe UDR UE subscription Data(including 5G VN Group) Error[%v]", err.Error())
	}

	// step 6: Policy Decision
	// PCF determines wherher UE policy need to be provisioned or updated,
	// and may determine Policy Control Request Trigger(s)
	if len(vnGroupConfigs) != 0 {
		logger.UEpolicylog.Info("Policy Decision: Create Ue Policy Management List!!")
		// URSP encoding
		urspByte, urspModel, err := BuildURSP(ue.Supi, vnGroupConfigs)
		if err != nil {
			logger.UEpolicylog.Errorln("BuildURSP err:", err.Error())
			return nil, nil, &models.ProblemDetails{
				Title:  "BuildEncodingURSP error",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
			}
		}

		// UE policy section management list encoding
		ueMcc, ueMnc := policyAssociationRequest.ServingPlmn.Mcc, policyAssociationRequest.ServingPlmn.Mnc
		uePolSecMngListContByte, uePolSecMngListContent, err := BuildUePolSecMngListCont(ueMcc, ueMnc, urspByte)
		if uePolSecMngListContByte == nil {
			logger.UEpolicylog.Debugln("uePolSecMngListContByte is nil !!")
		} else {
			logger.UEpolicylog.Warnf("uePolSecMngListContent : %+v\n", uePolSecMngListContent)
		}
		if err != nil {
			logger.UEpolicylog.Errorln("BuildUePolSecMngListCont err:", err.Error())
			return nil, nil, &models.ProblemDetails{
				Title:  "Build Ue_Policy_Section_ManageList_Content error",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
			}
		}
		// TODO: no iei info
		_, uePolicyManageList, err := BuildUePolSecMngList(0x00, uePolSecMngListContByte)
		if err != nil {
			logger.UEpolicylog.Errorln("BuildUePolSecMngList err:", err.Error())
			return nil, nil, &models.ProblemDetails{
				Title:  "Build Ue_Policy_Section_ManageList error",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
			}
		}
		// Get PTI from PCF context, ref to TS24.501 section-D.1.2 Principles of PTI handling for UE policy delivery service procedures
		// When the PCF initiates a procedure, the PCF shall use a PTI value in range between 80H and FEH.
		pti, err := pcfSelf.PTIGenerator.Allocate()
		if err != nil {
			logger.UEpolicylog.Errorln("Allocate_inRange err:", err.Error())
			return nil, nil, &models.ProblemDetails{
				Title:  "Get a new PTI from PCF context error",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
			}
		}

		logger.UEpolicylog.Warnln("PTI of UE Policy Container is ", pti)
		n1msgContainer, uePolicyContainer, err := BuildUePolContainer(*uePolicyManageList, pti)
		if err != nil {
			logger.UEpolicylog.Errorln("BuildUePolContainer err:", err.Error())
			return nil, nil, &models.ProblemDetails{
				Title:  "Build N1msgContainer[uePolicyDeliveryMsg_mang] error",
				Status: http.StatusInternalServerError,
				Detail: err.Error(),
			}
		}

		// step 10~15 : amf_N1N2 message Subs/Trans/Notify
		if n1msgContainer != nil {
			logger.UEpolicylog.Warnln("n1msgContainer is non-nil!!")
			// first, build the UePolicyContext in ue context
			// TODO: the index of ue policy stored in UE context can be replace
			uectxUepolData := ue.NewUePolicyData(assolId, policyAssociationRequest)
			uectxUepolData.SubscribePolicyID = subsUEPolicyDataId
			uectxUepolData.SubscribeSubscriptionID = subsSubscriptionDataId
			uectxUepolData.SuppFeat = "5GLAN-service"
			uectxUepolData.UePolicyContainer = uePolicyContainer
			uectxUepolData.UePolicyContainerListContent = *uePolSecMngListContent
			uectxUepolData.UrspRuleSet = *urspModel
			uectxUepolData.PTI = uePolicyContainer.GetHeaderPTI()
			logger.UEpolicylog.Warnln(" UE context UE policy PTI:", uectxUepolData.PTI)
			// send the n1n1 msg to AMF
			logger.UEpolicylog.Warnln("starting N1N2 msg Subscribe/Transfer...")
			UePolicy_N1N2msgProcess(ue, assolId, n1msgContainer, policyAssociationRequest)
		}
	} else {
		logger.UEpolicylog.Warnln("Policy Decision: Won't produce any Ue policy !!")
	}

	// TODO: add support feature
	// var requestSuppFeat openapi.SupportedFeature
	// if suppFeat, err := openapi.NewSupportedFeature(policyAssociationRequest.SuppFeat); err != nil {
	// 	logger.UEpolicylog.Errorln("ue policy NewSupportedFeature err:", err.Error())
	// } else {
	// 	requestSuppFeat = suppFeat
	// }
	// logger.UEpolicylog.Warnln("policyAssociationRequest.SuppFeat:", policyAssociationRequest.SuppFeat)
	// uePolicy.SuppFeat = pcfSelf.PcfSuppFeats[models.
	// 	ServiceName_NPCF_UE_POLICY_CONTROL].NegotiateWith(
	// 	requestSuppFeat).String()
	// if uePolicy.Rfsp != 0 {
	// 	response.Rfsp = uePolicy.Rfsp
	// }
	// response.SuppFeat = uePolicy.SuppFeat
	// if len(response.SuppFeat) == 0 {
	// 	response.SuppFeat = "5GLAN-service"
	// }

	// for the successfull case, the (V-)(H-)PCF shall send a HTTP "201 Created" response with the URI for the created resource in the "Location" header field
	// 3GPP TS 29.525 V17.9.0 (2022-12)-page.16
	var header http.Header = http.Header{
		"header": {locationHeader},
	}
	return header, &response, nil
}

func UePolicy_N1N2msgProcess(ue *pcf_context.UeContext, assolId string, n1msgContainer []uint8, polAssoReq models.PolicyAssociationRequest) error {
	go func() {
		time.Sleep(1 * time.Second)
		// N1 Message Subscribe Request
		logger.UEpolicylog.Warnln("Subscribe to notifications of N1 message by invoking amf_N1N2MessageSubscibe")
		if err := consumer.N1N2MessageSubscibe(polAssoReq); err != nil {
			logger.UEpolicylog.Errorln("N1N2MessageSubscibe error:", err.Error())
		}

		// N1N2 Message Transfer Request
		logger.UEpolicylog.Warnln("Start transfer N1 UE Policy via N1N2MessageTransfer")
		if err := consumer.N1N2MessageTransfer(n1msgContainer, polAssoReq); err != nil {
			logger.UEpolicylog.Errorln("N1N2MessageTransfer error:", err.Error())
		}

		// set timer T3501 for retransmisstion and release PTI of MANAGE UE POLICY COMMAND message
		if pcf_context.GetSelf().T3501Cfg.Enable {
			t3501Cfg := pcf_context.GetSelf().T3501Cfg
			logger.UEpolicylog.Warnln("Start T3501 timer")
			ue.T3501 = pcf_context.NewTimer(t3501Cfg.ExpireTime, t3501Cfg.MaxRetryTimes, func(expireTimes int32) {
				logger.UEpolicylog.Warnf("T3501 expires, retransmit [MANAGE UE POLICY COMMAND] (retry: %d)", expireTimes)
				// retransmit N1N2 Message Transfer Request
				logger.UEpolicylog.Warnln("Start transfer N1 UE Policy via N1N2MessageTransfer")
				if err := consumer.N1N2MessageTransfer(n1msgContainer, polAssoReq); err != nil {
					logger.UEpolicylog.Errorln("N1N2MessageTransfer error:", err.Error())
				}
			}, func() {
				logger.UEpolicylog.Warnf("T3501 expires %d times, abort N1N2transfer procedure", t3501Cfg.MaxRetryTimes)
				ue.T3501 = nil // clear the timer
				// refer to TS24501-D.2.1.5, PCF shall abort the procedure and release the allocated PTI.
				pcf_context.GetSelf().PTIGenerator.FreeID(int64(ue.UePolicyData[assolId].PTI))
				ue.UePolicyData[assolId] = nil
			})
		}
	}()
	return nil
}

// build the NAS message of ue policy for transport to UE through AMF, e.g. 5G group related info
func BuildUePolContainer(uePolmngList uePolicyContainer.UEPolicySectionManagementList, PTI int64) ([]byte, *uePolicyContainer.UePolicyContainer, error) {
	uePolContainer := uePolicyContainer.NewUePolDeliverySer()
	// set self-defined header first, let the encoding of later step more convenient
	uePolContainer.SetHeaderMessageType(uePolicyContainer.MsgTypeManageUEPolicyCommand)
	uePolContainer.SetHeaderPTI(uint8(PTI))

	// set UE Policy Container
	// set content of message type-ManageUEPolicyCommand. Tip: assignment for pointer is a reference data
	uePolContainer.ManageUEPolicyCommand = uePolicyContainer.NewManageUEPolicyCommand(uePolicyContainer.MsgTypeManageUEPolicyCommand)
	mngUEpolCommand := uePolContainer.ManageUEPolicyCommand
	mngUEpolCommand.SetPTI(uint8(PTI))
	mngUEpolCommand.UEPolicySectionManagementList = uePolmngList

	//encode the one of Message, e.g Gmm msg or Gsm msg or Upd msg
	rspByte, err := uePolContainer.UePolDeliverySerEncode()
	if err != nil {
		return nil, nil, err
	}
	return rspByte, uePolContainer, nil
}

// TODO: no IEI info
func BuildUePolSecMngList(iei uint8, buf []byte) ([]byte, *uePolicyContainer.UEPolicySectionManagementList, error) {
	var uePolSecMngLs uePolicyContainer.UEPolicySectionManagementList
	uePolSecMngLs.SetIei(iei)
	uePolSecMngLs.SetUEPolicySectionManagementListContent(buf)
	uePolSecMngLs.SetLen(uint16(len(buf)))
	buf, err := uePolSecMngLs.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return buf, &uePolSecMngLs, nil
}

func BuildUePolSecMngListCont(mcc, mnc string, uePolPartCont []uint8) ([]uint8, *uePolicyContainer.UEPolicySectionManagementListContent, error) {
	var uePolSecMngLsContent uePolicyContainer.UEPolicySectionManagementListContent
	var uePolSecMngSubLs uePolicyContainer.UEPolicySectionManagementSubList
	// 2 Octec length
	uePolSecMngSubLs.UpscGenerator = *uePolicyContainer.NewGenerator(1, 65535)
	mccInt, err := strconv.Atoi(mcc)
	if err != nil {
		return nil, nil, err
	}
	mncInt, err := strconv.Atoi(mnc)
	if err != nil {
		return nil, nil, err
	}
	uePolSecMngSubLs.SetPlmnDigit(mccInt, mncInt)
	var insturc uePolicyContainer.Instruction
	uPSC, err := uePolSecMngSubLs.UpscGenerator.Allocate()
	if err != nil {
		logger.UEpolicylog.Errorln("allocate UPSC of ue policy section management list error")
		return nil, nil, err
	} else {
		insturc.SetUpsc(uint16(uPSC))
	}
	var uePolPart uePolicyContainer.UEPolicyPart
	uePolPart.UEPolicyPartType.SetPartType(uePolicyContainer.UEPolicyPartType_URSP)
	// This content contains a encoded byte slice of "URSP or ANDSP or V2XP or ProSeP"
	uePolPart.SetPartContent(uePolPartCont)
	logger.UEpolicylog.Debugf("uePolPartCont: %v", uePolPartCont)
	insturc.UEPolicySectionContents = append(insturc.UEPolicySectionContents, uePolPart)
	uePolSecMngSubLs.UEPolicySectionManagementSubListContents.AppendInstruction(insturc)
	uePolSecMngLsContent.AppendSublist(uePolSecMngSubLs)

	contByte, err := uePolSecMngLsContent.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return contByte, &uePolSecMngLsContent, nil
}

func BuildURSPrule_Default() (*ben_models.URSPrule, error) {
	// Make Default URSP rule
	var defaultUrspRule ben_models.URSPrule
	defaultUrspRule.PrecedenceValue = 255
	// Traffic Descriptor: Match_ALL_Type
	{
		var defaultTrafDescComp ben_models.TrafficDescriptorComponent
		defaultTrafDescComp.Identifier = ben_models.Traf_Match_all_type
		defaultTrafDescComp.Value = nil
		defaultUrspRule.TrafficDescriptor = append(defaultUrspRule.TrafficDescriptor, defaultTrafDescComp)
		logger.UEpolicylog.Debugf("[BuildURSPrule_Default][TrafficDescriptorComponent] default: %+v\n", defaultTrafDescComp)
	}
	// Route Descriptor: set routing to [SNSSAI-0x010202] with [DNN-Internet]
	{
		var defaultRouDesc ben_models.RouteSelectionDescriptor
		defaultRouDesc.PrecedenceValue = 0
		{ // component1 : SNSSAI-0x010203
			var defaultRouDescComp1 ben_models.RouteSelectionComponent
			defaultRouDescComp1.Identifier.SetTypeId(ben_models.Route_S_NSSAI_type)
			defaultSd, err := hex.DecodeString(pcf_context.GetSelf().DefaultSNSSAI.Sd)
			if err != nil {
				logger.UEpolicylog.Warnf("decode Default SNSSAI-SD of URSP Rule err:%s\n", err.Error())
			}
			byteSNSSAI := defaultRouDescComp1.MakeByte_SNSSAI(uint8(pcf_context.GetSelf().DefaultSNSSAI.Sst), defaultSd)
			if err := defaultRouDescComp1.SetValue(byteSNSSAI); err != nil {
				return nil, err
			}
			defaultRouDesc.RouteSelectionContent = append(defaultRouDesc.RouteSelectionContent, defaultRouDescComp1)
			logger.UEpolicylog.Debugf("[BuildURSPrule_Default][RouteSelectionComponent] default 1: %+v\n", defaultRouDescComp1)
		}
		{ // component2: DNN-Internet
			var defaultRouDescComp2 ben_models.RouteSelectionComponent
			defaultRouDescComp2.Identifier.SetTypeId(ben_models.Route_DNN_type)
			logger.UEpolicylog.Warnln("BuildURSPrule_Default: dnn-", pcf_context.GetSelf().DefaultDNN)
			byteDNN := defaultRouDescComp2.MakeByte_DNN(pcf_context.GetSelf().DefaultDNN)
			if err := defaultRouDescComp2.SetValue(byteDNN); err != nil {
				return nil, err
			}
			defaultRouDesc.RouteSelectionContent = append(defaultRouDesc.RouteSelectionContent, defaultRouDescComp2)
			logger.UEpolicylog.Debugf("[BuildURSPrule_Default][RouteSelectionComponent] default 2: %+v\n", defaultRouDescComp2)
		}
		defaultUrspRule.RouteSelectionDescriptorList = append(defaultUrspRule.RouteSelectionDescriptorList, defaultRouDesc)
		logger.UEpolicylog.Debugf("[BuildURSPrule_Default][RouteSelectionDescriptor] default: %+v\n", defaultRouDesc)
	}
	return &defaultUrspRule, nil
}

func BuildURSPrule_VnGroup(precd uint8, vnGroupCfg ben_models.Model5GvnGroupConfiguration) (*ben_models.URSPrule, error) {
	// Make VN Group URSP rule
	var gpUrspRule ben_models.URSPrule
	gpUrspRule.PrecedenceValue = precd
	// Traffic Descriptor: Subnet IP field
	{
		var trafDescComp ben_models.TrafficDescriptorComponent
		trafDescComp.Identifier = ben_models.Traf_IPv4_remote_addr_type
		subnetIP := strings.Split(vnGroupCfg.SubnetIP.Ipv4Addr, "/")
		if len(subnetIP) != 2 {
			return nil, fmt.Errorf("subnet IP of GroupConfig-[%s] should contain IP and Mask-[%s]", vnGroupCfg.InternalGroupIdentifier, vnGroupCfg.SubnetIP)
		}
		var mask string
		{
			maskInt, err := strconv.Atoi(subnetIP[1])
			if err != nil {
				return nil, fmt.Errorf("slash subnet IP should number, e.g. 8.8.8.8/32")
			}
			cnt := 0
			for (maskInt - 8) >= 0 {
				if cnt < 3 {
					mask += "255."
				} else {
					mask += "255"
				}
				cnt += 1
				maskInt -= 8
			}
			for i := cnt; i <= 3; i++ {
				if maskInt > 0 {
					mask += strconv.Itoa(2 ^ maskInt)
					maskInt = 0
				} else {
					mask += "0"
				}
				if i != 3 {
					mask += "."
				}
			}
		}
		byetSubnetIp, err := trafDescComp.IPv4remote_MakeByte(subnetIP[0], mask)
		if err != nil {
			return nil, fmt.Errorf("the ipv4 addr of VN group subnet IP doesn't follow format [IP/Mask], err:%v", err.Error())
		}
		trafDescComp.SetValue(byetSubnetIp)
		gpUrspRule.TrafficDescriptor = append(gpUrspRule.TrafficDescriptor, trafDescComp)
	}
	// Route Descriptor: set routing to [SNSSAI] with [DNN]
	{
		var rouDesc ben_models.RouteSelectionDescriptor
		rouDesc.PrecedenceValue = 0
		{
			// component1 : SNSSAI
			var rouDescComp1 ben_models.RouteSelectionComponent
			rouDescComp1.Identifier.SetTypeId(ben_models.Route_S_NSSAI_type)
			// sst - 3 Octets
			sstBuf := bytes.NewBuffer(nil)
			if err := binary.Write(sstBuf, binary.BigEndian, vnGroupCfg.Var5gVnGroupData.SNssai.Sst); err != nil {
				return nil, err
			}
			// sd - 1 Octets
			byteSD, err := hex.DecodeString(vnGroupCfg.Var5gVnGroupData.SNssai.Sd)
			if err != nil {
				return nil, err
			}
			byteSNSSAI := rouDescComp1.MakeByte_SNSSAI(sstBuf.Bytes()[len(sstBuf.Bytes())-1], byteSD)
			if err := rouDescComp1.SetValue(byteSNSSAI); err != nil {
				return nil, err
			}
			rouDesc.RouteSelectionContent = append(rouDesc.RouteSelectionContent, rouDescComp1)
		}
		{
			// component2: DNN
			var rouDescComp2 ben_models.RouteSelectionComponent
			rouDescComp2.Identifier.SetTypeId(ben_models.Route_DNN_type)
			logger.UEpolicylog.Warnln("BuildURSPrule_VnGroup: dnn-", vnGroupCfg.Var5gVnGroupData.Dnn)
			byteDNN := rouDescComp2.MakeByte_DNN(vnGroupCfg.Var5gVnGroupData.Dnn)
			if err := rouDescComp2.SetValue(byteDNN); err != nil {
				return nil, err
			}
			rouDesc.RouteSelectionContent = append(rouDesc.RouteSelectionContent, rouDescComp2)
		}
		{
			// component3: PDU session type
			var rouDescComp3 ben_models.RouteSelectionComponent
			rouDescComp3.Identifier.SetTypeId(ben_models.Route_PDU_session_type_type)
			pduType, _ := rouDescComp3.MakeByte_PDUsessType(strings.ToLower(string(vnGroupCfg.Var5gVnGroupData.PduSessionTypes[0])))
			logger.UEpolicylog.Warnf("pduType of VN 5G group: %v\n", pduType)
			if err := rouDescComp3.SetValue(pduType); err != nil {
				return nil, err
			}
			rouDesc.RouteSelectionContent = append(rouDesc.RouteSelectionContent, rouDescComp3)
		}
		gpUrspRule.RouteSelectionDescriptorList = append(gpUrspRule.RouteSelectionDescriptorList, rouDesc)
	}
	return &gpUrspRule, nil
}

func BuildURSP(supi string, vnGroupCfg_Set map[string]ben_models.Model5GvnGroupConfiguration) ([]byte, *ben_models.UePolicyURSP, error) {
	var urspRuleSet ben_models.UePolicyURSP
	precd := 0
	// URSP rule - for VN Group
	for _, groupConfig := range vnGroupCfg_Set {
		gpUrspRule, err := BuildURSPrule_VnGroup(uint8(precd), groupConfig)
		if err != nil {
			return nil, nil, err
		}
		precd += 1
		urspRuleSet.URSPruleSet = append(urspRuleSet.URSPruleSet, *gpUrspRule)
		logger.UEpolicylog.Debugf("[BuildURSP] Group UrspRule:%+v\n", *gpUrspRule)
	}

	// URSP rule - for default use
	defUrspRule, err := BuildURSPrule_Default()
	if err != nil {
		return nil, nil, err
	}
	urspRuleSet.URSPruleSet = append(urspRuleSet.URSPruleSet, *defUrspRule)
	logger.UEpolicylog.Debugf("[BuildURSP] Default UrspRule:%+v\n", *defUrspRule)

	// Encoding Whole URSP to byte slice then return
	byteURSP, err := urspRuleSet.EncodeURSP()
	logger.UEpolicylog.Warnf("[BuildURSP] URSP RuleSet: %+v\n", urspRuleSet)
	logger.UEpolicylog.Debugf("[BuildURSP]byteURSP: %+v\n", byteURSP)
	if err != nil {
		return nil, nil, err
	}
	return byteURSP, &urspRuleSet, nil

}
