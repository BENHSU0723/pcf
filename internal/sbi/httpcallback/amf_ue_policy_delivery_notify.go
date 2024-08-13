package httpcallback

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pcf/internal/logger"
	"github.com/free5gc/pcf/internal/sbi/producer"
	"github.com/free5gc/util/httpwrapper"
)

// AMF ontify PCF that the UE policy have been transfer to UE successful,
// including UE Policy container from UE contained in NAS msg
func HTTPAmfUePolicyDeliveryNotify(c *gin.Context) {
	var n1MessageNotify models.N1MessageNotify
	n1MessageNotify.JsonData = new(models.N1MessageNotification)

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CallbackLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	contentType := c.GetHeader("Content-Type")
	s := strings.Split(contentType, ";")
	switch s[0] {
	case "application/json":
		err = fmt.Errorf("BinaryDataN1Message is Empty in N1MessageNotify")
	case "multipart/related":
		err = openapi.Deserialize(&n1MessageNotify, requestBody, contentType)
	default:
		err = fmt.Errorf("Wrong content type")
	}
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, n1MessageNotify)
	req.Params["supi"] = c.Params.ByName("supi")

	rsp := producer.HandleAmfUePolicyDeliveryNotify(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.CallbackLog.Errorln(err)
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
