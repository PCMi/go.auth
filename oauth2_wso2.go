package auth

import (
	"net/http"
	"fmt"
	//"net/url"
	"io/ioutil"
	"encoding/json"
	
	"github.com/davecgh/go-spew/spew"
)

type Wso2User struct {
	UserName     interface{} `json:"name"`
	FamilyName interface{} `json:"family_name"`
	PreferredName interface{} `json:"preferred_username"`
	GivenName interface{} `json:"given_name"`
	
	UserEmail    interface{} `json:"email"`
}

func (u *Wso2User) Id() string       { 
	if u.UserName == nil { return "" }; 
	return u.UserName.(string) 
	}

func (u *Wso2User) Provider() string { return "Wso2.com" }

// Below fields need to be parsed as interface{} and converted to String
// because Golang (as of version 1.0) does not support parsing JSON Strings
// with an explicit null value.

func (u *Wso2User) Name() string {
	if u.UserName == nil { return "" }; 
	return u.UserName.(string)
}

func (u *Wso2User) Email() string {
	if u.UserEmail == nil { return "" }
	return u.UserEmail.(string)
}

func (u *Wso2User) Link() string {
	//if u.UserLink == nil { return "" }
	//return u.UserLink.(string)
	return ""
}

func (u *Wso2User) Picture() string {
	//if u.UserGravatar == nil { return "" }
	// use the Gravatar Id instead of the Avatar URL, which has a bunch
	// of un-necessary data (as far as I can tell) appended to the end.
	//return "https://secure.gravatar.com/avatar/" + u.UserGravatar.(string)
	return ""
}

func (u *Wso2User) Org() string {
	//if u.UserCompany == nil { return "" }
	//return u.UserCompany.(string)
	return ""
}


// Wso2Provider is an implementation of Wso2's Oauth2 protocol.
// See http://developer.Wso2.com/v3/oauth/
type Wso2Provider struct {
	OAuth2Mixin
	Scope string
}

// NewWso2Provider allocates and returns a new Wso2Provider.
func NewWso2Provider(clientId, clientSecret, scope string, redir string) *Wso2Provider {
	wso2 := Wso2Provider{}
	wso2.AuthorizationURL = "https://idm.rxwiki.com/oauth2/authorize"
	wso2.AccessTokenURL   = "https://idm.rxwiki.com/oauth2/token"
	wso2.ClientId         = clientId
	wso2.ClientSecret     = clientSecret
	wso2.Scope            = scope
	//Wso2.Scope            = scope
	wso2.OAuth2Mixin.RedirectURL = redir //"http://jeff-beego.rxwiki.com/auth/login"
	// default the Scope if not provided
	if len(wso2.Scope) == 0 {
		wso2.Scope = "user:email"
	}
	return &wso2
}

// Redirect will do an http.Redirect, sending the user to the Wso2 login
// screen.
func (self *Wso2Provider) Redirect(w http.ResponseWriter, r *http.Request) {
	self.OAuth2Mixin.AuthorizeRedirect(w, r, self.Scope)
}

// GetAuthenticatedUser will retrieve the Authentication User from the
// http.Request object.
func (self *Wso2Provider) GetAuthenticatedUser(w http.ResponseWriter, r *http.Request) (User, Token, error) {

	// Get the OAuth2 Access Token
	token, err := self.GetAccessToken(r)
	if err != nil {
		return nil, nil, err
	}

	user := Wso2User{}
	
	//err = self.OAuth2Mixin.GetAuthenticatedUser("https://api.github.com/user", token.AccessToken, &user)
	//err = self.OAuth2Mixin.GetAuthenticatedUser("https://idm.rxwiki.com/oauth2/userinfo?schema=openid", token.AccessToken, &user)
	//err = self.OAuth2Mixin.GetAuthenticatedUser("https://idm.rxwiki.com/oauth2/userinfo?scope=user:email", token.AccessToken, &user)
	err = self.GetAuthenticatedUserBearer("https://idm.rxwiki.com/oauth2/userinfo?schema=openid", token.AccessToken, &user, "schema=openid")
	fmt.Println("user data ", err, user)
	fmt.Println(token.AccessToken)
	spew.Dump(user)
	return &user, token, err
}

// Gets the Authenticated User
func (self *Wso2Provider) GetAuthenticatedUserBearer(endpoint string, accessToken string, resp interface{}, params string) error {
/*
	//create the user url
	endpointUrl, _ := url.Parse(endpoint)
	//endpointUrl.RawQuery = "access_token="+accessToken //+"&schema=openid"
	endpointUrl.RawQuery = params
fmt.Println("---------------------", endpointUrl)
	//create the http request for the user Url
	req := http.Request{
		URL:        endpointUrl,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
	}
	*/
	
	client := &http.Client{}
	
	nReq, err := http.NewRequest("GET", endpoint, nil)
	nReq.Header.Set("Authorization", "Bearer " + accessToken)
	r, err := client.Do(nReq)
	//do the http request and get the response
	//r, err := http.DefaultClient.Do(&req)
	if err != nil {
		return err
	}

	//get the response body
	userData, err := ioutil.ReadAll(r.Body)
	fmt.Println("GetAuthenticatedUserBearer get user data", userData)
	spew.Dump(userData)
	defer r.Body.Close()
	if err != nil {
		return err
	}

	//unmarshal user json
	return json.Unmarshal(userData, &resp)
}


