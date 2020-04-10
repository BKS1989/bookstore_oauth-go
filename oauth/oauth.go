package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/bks1989/bookstore_oauth-go/oauth/errors"
	"net/http"
	"strconv"
	"strings"
	"github.com/mercadolibre/golang-restclient/rest"
	"time"
)

const (
	headerXPublic = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramsAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)
type accessToken struct {
	AccessToken string `json:"access_token"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

type oauthInterface interface {
	
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId),10,64)
	if err != nil {
		return 0
	}
	return callerId
}
func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId),10,64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramsAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccesToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXCallerId,fmt.Sprintf("%v",at.UserId))
	request.Header.Add(headerXClientId,fmt.Sprintf("%v",at.ClientId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXCallerId)
	request.Header.Del(headerXClientId)
}
func getAccesToken(accessTokenId string) (*accessToken,*errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s",accessTokenId))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response while logging to user")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(),&restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error inteface while trying to login to user")
		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(),&at); err != nil {
		return nil, errors.NewInternalServerError("error while unmarshal user response")
	}
	return &at, nil
}

