package aps

import (
	"net/http"
	"testing"
	"errors"
		
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

type ParamsTest struct {
	Code string
}

type Token struct {
	AccessToken       string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Expires string `json:"expires_in"`
}

type BadToken struct {
	AccessToken       string `json:"xx"`
	TokenType    string `json:"xx2"`
	Expires string `json:"xx3"`
}

func (p ParamsTest) Get(param string) (string) {
	return p.Code
}

func TestOK(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback","scope1","scope2")

	httpmock.Activate()
    defer httpmock.DeactivateAndReset()
	token := &Token{
				"t1",
				"type1",
				"10000",
				}
    httpmock.RegisterResponder("POST", "http://localhost:9096/token",
         func(req *http.Request) (*http.Response, error) {
			var resp *http.Response
			var err error
			if (req.FormValue("code")=="1"){
				resp, err = httpmock.NewJsonResponse(200, token)
			}else{
				 resp = httpmock.NewStringResponse(500, "")
			}
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	session, _ := testaps.BeginAuth("")
	params := ParamsTest {
		Code:"1",
	}
	returnedToken,err := session.Authorize(testaps,params)
	assert.Nil(t, err)
	assert.Equal(t, returnedToken, "t1", "Token should be equal")	
}


func TestBadCode(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback","scope1","scope2")

	httpmock.Activate()
    defer httpmock.DeactivateAndReset()
	
	token := &Token{
				"t1",
				"type1",
				"10000",
				}
    httpmock.RegisterResponder("POST", "http://localhost:9096/token",
        func(req *http.Request) (*http.Response, error) {
			var resp *http.Response
			var err error
			if (req.FormValue("code")=="1"){
				resp, err = httpmock.NewJsonResponse(200, token)
			}else{
				 resp = httpmock.NewStringResponse(500, "")
			}
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	session, _ := testaps.BeginAuth("")
	params := ParamsTest {
		Code:"2",
	}
	returnedToken,err := session.Authorize(testaps,params)
	assert.NotNil(t, err)
	assert.Equal(t, returnedToken, "", "Token should be equal")	
}


func TestBadToken(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback","scope1","scope2")

	httpmock.Activate()
    defer httpmock.DeactivateAndReset()
	
	token := &BadToken{
				"t1",
				"type1",
				"10000",
				}
    httpmock.RegisterResponder("POST", "http://localhost:9096/token",
        func(req *http.Request) (*http.Response, error) {
			var resp *http.Response
			var err error
			if (req.FormValue("code")=="1"){
				resp, err = httpmock.NewJsonResponse(200, token)
			}else{
				 resp = httpmock.NewStringResponse(500, "")
			}
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	session, _ := testaps.BeginAuth("")
	params := ParamsTest {
		Code:"1",
	}
	returnedToken,err := session.Authorize(testaps,params)
	assert.NotNil(t, err)
	assert.Equal(t, err, errors.New("Invalid token received from provider"), "Unexpected error")	
	assert.Equal(t, returnedToken, "", "Token should be equal")	
}