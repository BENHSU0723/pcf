/*
 * Npcf_UEPolicyControl
 *
 * UE Policy Control Service API
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package uepolicy

import (
	"net/http"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/producer"
	"github.com/free5gc/pcf/internal/util"
	"github.com/free5gc/util/httpwrapper"
	"github.com/gin-gonic/gin"
)

// PoliciesPolAssoIdDelete -
func PoliciesPolAssoIdDelete(c *gin.Context) {
}

// PoliciesPolAssoIdGet -
func PoliciesPolAssoIdGet(c *gin.Context) {
}

// PoliciesPolAssoIdUpdatePost -
func PoliciesPolAssoIdUpdatePost(c *gin.Context) {
}

// PoliciesPost -UE policy request from the AMF which receives the registration request from the AN
func PoliciesPost(c *gin.Context) {
	logger.UEpolicylog.Info("Receive UEpolicy post request !!")
	var policyAssociationRequest models.PolicyAssociationRequest

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.UEpolicylog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&policyAssociationRequest, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.UEpolicylog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	if policyAssociationRequest.Supi == "" || policyAssociationRequest.NotificationUri == "" {
		rsp := util.GetProblemDetail("Miss Mandotory IE", util.ERROR_REQUEST_PARAMETERS)
		logger.UEpolicylog.Errorln(rsp.Detail)
		c.JSON(int(rsp.Status), rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, policyAssociationRequest)
	//optional input parameter
	req.Params["polAssoId"], _ = c.Params.Get("polAssoId")

	rsp := producer.HandlePostUePolicyRequest(req)

	for key, val := range rsp.Header {
		c.Header(key, val[0])
	}

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.UEpolicylog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}
}