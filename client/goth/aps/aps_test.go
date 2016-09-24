package aps

import (
	"net/http"
	"testing"
	
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Location string `json:"location"`
}

func TestNewOK(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback")
	assert.Equal(t, testaps.ClientKey,"testKey", "Client Key Invalid")
	assert.Equal(t, testaps.Secret,"testSecret", "Client Secret Invalid")
	assert.Equal(t, testaps.CallbackURL,"callback", "Callback url Invalid")
	assert.Equal(t, testaps.config.ClientID,"testKey", "Config Client Key Invalid")
	assert.Equal(t, testaps.config.ClientSecret,"testSecret", "Config Client Secret Invalid")
	assert.Equal(t, testaps.config.RedirectURL,"callback", "Config Callback url Invalid")
	assert.Equal(t, testaps.config.Endpoint.AuthURL,"http://localhost:9096/authorize", "Config endpoint AuthURL url Invalid")
	assert.Equal(t, testaps.config.Endpoint.TokenURL,"http://localhost:9096/token", "Callback endpoint Token URL Invalid")
}

func TestNewScopes(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback","scope1","scope2")
	assert.Equal(t, testaps.ClientKey,"testKey", "Client Key Invalid")
	assert.Equal(t, testaps.Secret,"testSecret", "Client Secret Invalid")
	assert.Equal(t, testaps.CallbackURL,"callback", "Callback url Invalid")
	assert.Equal(t, testaps.config.ClientID,"testKey", "Config Client Key Invalid")
	assert.Equal(t, testaps.config.ClientSecret,"testSecret", "Config Client Secret Invalid")
	assert.Equal(t, testaps.config.RedirectURL,"callback", "Config Callback url Invalid")
	assert.Equal(t, testaps.config.Endpoint.AuthURL,"http://localhost:9096/authorize", "Config endpoint AuthURL url Invalid")
	assert.Equal(t, testaps.config.Endpoint.TokenURL,"http://localhost:9096/token", "Callback endpoint Token URL Invalid")
	assert.Equal(t, testaps.config.Scopes[0],"scope1", "Scope Invalid")
	assert.Equal(t, testaps.config.Scopes[1],"scope2", "Scope Invalid")
}
	
func TestFetchUser(t *testing.T) {
    httpmock.Activate()
    defer httpmock.DeactivateAndReset()

	user1 := &User{
				"1",
				"test@test.com",
				"localhost",
			}
	user2 := &User{
				"2",
				"test2@test.com",
				"localhost",
			}		
     
    httpmock.RegisterResponder("GET", "http://localhost:9096/userinfo?access_token=1",
        func(req *http.Request) (*http.Response, error) {
            resp, err := httpmock.NewJsonResponse(200, user1)
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	 httpmock.RegisterResponder("GET", "http://localhost:9096/userinfo?access_token=2",
        func(req *http.Request) (*http.Response, error) {
            resp, err := httpmock.NewJsonResponse(200, user2)
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	testaps:=New("testKey", "testSecret", "callback")
	session := &Session{
		AuthURL: "",
		AccessToken:"1",
	}
	gothuser,error :=testaps.FetchUser(session);
	
	assert.Nil(t, error)
	assert.Equal(t, gothuser.UserID, "1", "Error user ID Invalid")	
	assert.Equal(t, gothuser.Email, "test@test.com", "Error email Invalid")	
	assert.Equal(t, gothuser.Location, "localhost", "Error location Invalid")	
}

func TestFetchUserNonExisting(t *testing.T) {
    httpmock.Activate()
    defer httpmock.DeactivateAndReset()

	user := &User{
				"1",
				"test@test.com",
				"localhost",
			}
     
    httpmock.RegisterResponder("GET", "http://localhost:9096/userinfo?access_token=1",
        func(req *http.Request) (*http.Response, error) {
            resp, err := httpmock.NewJsonResponse(200, user)
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	 httpmock.RegisterResponder("GET", "http://localhost:9096/userinfo?access_token=2",
        func(req *http.Request) (*http.Response, error) {
            resp, err := httpmock.NewJsonResponse(200, user)
            if err != nil {
                return httpmock.NewStringResponse(500, ""), nil
            }
            return resp, nil
        },
    )
	
	testaps:=New("testKey", "testSecret", "callback")
	session := &Session{
		AuthURL: "",
		AccessToken:"3",
	}
	gothuser,error :=testaps.FetchUser(session);
	assert.NotNil(t, error)
	assert.NotEqual(t, gothuser.UserID, "1", "Error user ID Invalid")	
	assert.NotEqual(t, gothuser.Email, "test@test.com", "Error email Invalid")	
	assert.NotEqual(t, gothuser.Location, "localhost", "Error location Invalid")	
}

func TestBeginAuth(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback")
	session, error := testaps.BeginAuth("")
	assert.Nil(t, error)
	url,error := session.GetAuthURL();
	assert.Nil(t, error)
	assert.Equal(t, url, "http://localhost:9096/authorize?client_id=testKey&redirect_uri=callback&response_type=code", "Invalid url")	
}

func TestPrompt(t *testing.T) {
	testaps:=New("testKey", "testSecret", "callback")
	testaps.SetPrompt("Offline");
	session, error := testaps.BeginAuth("")
	assert.Nil(t, error)
	url,error := session.GetAuthURL();
	assert.Nil(t, error)
	assert.Equal(t, url, "http://localhost:9096/authorize?client_id=testKey&prompt=Offline&redirect_uri=callback&response_type=code", "Invalid url")	
}
