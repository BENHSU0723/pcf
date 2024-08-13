package util

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/BENHSU0723/nas_public/uePolicyContainer"
	ben_models "github.com/BENHSU0723/openapi_public/models"
	"github.com/free5gc/openapi/models"
)

var policyTriggerArray = []models.PolicyControlRequestTrigger{
	models.PolicyControlRequestTrigger_PLMN_CH,
	models.PolicyControlRequestTrigger_RES_MO_RE,
	models.PolicyControlRequestTrigger_AC_TY_CH,
	models.PolicyControlRequestTrigger_UE_IP_CH,
	models.PolicyControlRequestTrigger_UE_MAC_CH,
	models.PolicyControlRequestTrigger_AN_CH_COR,
	models.PolicyControlRequestTrigger_US_RE,
	models.PolicyControlRequestTrigger_APP_STA,
	models.PolicyControlRequestTrigger_APP_STO,
	models.PolicyControlRequestTrigger_AN_INFO,
	models.PolicyControlRequestTrigger_CM_SES_FAIL,
	models.PolicyControlRequestTrigger_PS_DA_OFF,
	models.PolicyControlRequestTrigger_DEF_QOS_CH,
	models.PolicyControlRequestTrigger_SE_AMBR_CH,
	models.PolicyControlRequestTrigger_QOS_NOTIF,
	models.PolicyControlRequestTrigger_NO_CREDIT,
	models.PolicyControlRequestTrigger_PRA_CH,
	models.PolicyControlRequestTrigger_SAREA_CH,
	models.PolicyControlRequestTrigger_SCNN_CH,
	models.PolicyControlRequestTrigger_RE_TIMEOUT,
	models.PolicyControlRequestTrigger_RES_RELEASE,
	models.PolicyControlRequestTrigger_SUCC_RES_ALLO,
	models.PolicyControlRequestTrigger_RAT_TY_CH,
	models.PolicyControlRequestTrigger_REF_QOS_IND_CH,
	models.PolicyControlRequestTrigger_NUM_OF_PACKET_FILTER,
	models.PolicyControlRequestTrigger_UE_STATUS_RESUME,
	models.PolicyControlRequestTrigger_UE_TZ_CH,
}

// func GetSMPolicyKey(snssai *models.Snssai, dnn string) string {
// 	if snssai == nil || len(snssai.Sd) != 6 || dnn == "" {
// 		return ""
// 	}
// 	return fmt.Sprintf("%02x%s-%s", snssai.Sst, snssai.Sd, dnn)
// }

// Convert Snssai form models to hexString(sst(2)+sd(6))
func SnssaiModelsToHex(snssai models.Snssai) string {
	sst := fmt.Sprintf("%02x", snssai.Sst)
	return sst + snssai.Sd
}

// Use BitMap to generate requested policy control triggers,
// 1 means yes, 0 means no, see subscaulse 5.6.3.6-1 in TS29512
func PolicyControlReqTrigToArray(bitMap uint64) (trigger []models.PolicyControlRequestTrigger) {
	cnt := 0
	size := len(policyTriggerArray)
	for bitMap > 0 && cnt < size {
		if (bitMap & 0x01) > 0 {
			trigger = append(trigger, policyTriggerArray[cnt])
		}
		bitMap >>= 1
		cnt++
	}
	return
}

func UePolicyContentToModelUePolicySection(mngListContent uePolicyContainer.UEPolicySectionManagementListContent, ursp ben_models.UePolicyURSP) (*ben_models.UePolicySet, error) {
	// UE generally only have all UE Policys in single PLMN, so just retrive first one.
	var mcc, mnc, upsc string
	for _, subList := range mngListContent {
		if subList.Mcc != nil && subList.Mnc != nil {
			mcc = strconv.Itoa(*subList.Mcc)
			mnc = strconv.Itoa(*subList.Mnc)
			for _, instruction := range subList.UEPolicySectionManagementSubListContents {
				if instruction.Upsc != 0 {
					upsc = strconv.Itoa(int(instruction.Upsc))
				}
			}
			break
		}
	}

	var sliceBasedRouSelDescList []ben_models.SnssaiRouteSelectionDescriptor
	for _, urspRule := range ursp.URSPruleSet {
		for _, routeDesc := range urspRule.RouteSelectionDescriptorList {
			var sliceBasedRouSelDesc ben_models.SnssaiRouteSelectionDescriptor
			var dnnRouSelDesc ben_models.DnnRouteSelectionDescriptor
			for _, routeDescComp := range routeDesc.RouteSelectionContent {
				switch typeId := routeDescComp.Identifier; typeId {
				case ben_models.Route_DNN_type:
					dnnRouSelDesc.Dnn = string(routeDescComp.Value[1:])
				case ben_models.Route_PDU_session_type_type:
					pduType := resolvePDUsessType(routeDescComp.Value[0])
					dnnRouSelDesc.PduSessTypes = append(dnnRouSelDesc.PduSessTypes, ben_models.PduSessionType(pduType))
				case ben_models.Route_S_NSSAI_type:
					if err := decodeSliceInfo2Desc(routeDescComp.Value, &sliceBasedRouSelDesc); err != nil {
						return nil, err
					}
				}
			}
			// if all value are fulfill, it's a valid Descriptor
			if dnnRouSelDesc.Dnn != "" && sliceBasedRouSelDesc.Snssai.Sst != 0 {
				sliceBasedRouSelDesc.DnnRouteSelDescs = append(sliceBasedRouSelDesc.DnnRouteSelDescs, dnnRouSelDesc)
				sliceBasedRouSelDescList = append(sliceBasedRouSelDescList, sliceBasedRouSelDesc)
			}
		}
	}

	plmnRouteSelDesc := ben_models.PlmnRouteSelectionDescriptor{
		ServingPlmn:         ben_models.PlmnId{Mcc: mcc, Mnc: mnc},
		SnssaiRouteSelDescs: sliceBasedRouSelDescList,
	}
	plmnStr := fmt.Sprintf("%s-%s", mcc, mnc)
	upsi := plmnStr + "-" + upsc

	rspUePolSet := ben_models.UePolicySet{
		UePolicySections: map[string]ben_models.UePolicySection{
			// TODO: I don't know what info should be UePolicySectionInfo
			upsc: {UePolicySectionInfo: "These UE policys have been executed successfully by UE", Upsi: upsi},
		},
		AllowedRouteSelDescs: map[string]ben_models.PlmnRouteSelectionDescriptor{
			plmnStr: plmnRouteSelDesc,
		},
		SuppFeat: "5GLAN-service",
	}

	return &rspUePolSet, nil
}

func decodeSliceInfo2Desc(sliceValue []uint8, sliceBasedRouSelDesc *ben_models.SnssaiRouteSelectionDescriptor) error {
	// decode sst
	var sstRoute int8
	buf := bytes.NewBuffer(sliceValue[3:4])
	if err := binary.Read(buf, binary.BigEndian, &sstRoute); err != nil {
		return fmt.Errorf("Decode SST of Route Selection Descriptor Component error:%v", err.Error())
	}
	sliceBasedRouSelDesc.Snssai.Sst = int32(sstRoute)

	if sliceValue[2] == 0x01 { //only sst
		return nil
	} else if sliceValue[2] == 0x04 { //sst and sd
		// decode sd
		sdRoute := hex.EncodeToString(sliceValue[4:7])
		sliceBasedRouSelDesc.Snssai.Sd = sdRoute
	} else {
		return fmt.Errorf("only support SNSSAI type 0x01 or 0x04")
	}

	return nil
}

// ref to TS 124 501 V17.7.1, 9.11.4.11 PDU session type
func resolvePDUsessType(value uint8) string {

	if value == 0x01 {
		return "IPV4"
	} else if value == 0x02 {
		return "IPV6"
	} else if value == 0x03 {
		return "IPV4V6"
	} else if value == 0x04 {
		return "UNSTRUCTURED"
	} else if value == 0x05 {
		return "ETHERNET"
	} else if value == 0x07 {
		return "RESERVED"
	}
	// All other values are unused and shall be interpreted as "IPv4v6", if received by the UE or the network.
	return "IPV4V6"
}
