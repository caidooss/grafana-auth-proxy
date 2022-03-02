package grafana

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrOrgNotFound  = errors.New("organisation not found")
	ErrUserNotFound = errors.New("user not found")
)

type GrafanaClient struct {
	basicAuthEnc string
	baseURL      string
}

func NewGrafanaClient(username, password, baseURL string) *GrafanaClient {
	basicAuth := username + ":" + password
	basicAuthEnc := base64.StdEncoding.EncodeToString([]byte(basicAuth))

	return &GrafanaClient{
		basicAuthEnc: basicAuthEnc,
		baseURL:      baseURL,
	}
}

type GetOrgByNameResponse struct {
	Name string `json:"name"`
	ID   int64  `json:"id"`
}

type GetUserByEmailResponse struct {
	Email string `json:"email"`
	ID    int64  `json:"id"`
}

type CreateOrgRequest struct {
	Name string `json:"name"`
}

type CreateOrgResponse struct {
	OrgId   int64  `json:"orgId"`
	Message string `json:"message"`
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	OrgId    int64  `json:"OrgId"`
	Login    string `json:"login"`
}

type CreateUserResponse struct {
	ID      int64  `json:"id"`
	Message string `json:"message"`
}

type AddUserToOrgRequest struct {
	LoginOrEmail string `json:"loginOrEmail"`
	Role         string `json:"role"`
}

type AddUserToOrgResponse struct {
	UserID  int64  `json:"userId"`
	Message string `json:"message"`
}

type UserInOrgResponse struct {
	CreateUserRequest
}

type SwitchUserResponse struct {
	Message string `json:"message"`
}

type UpdateUserOrgRole struct {
	Role string `json:"role"`
}

// Get organisation by name
func (g *GrafanaClient) GetOrgByName(name string) (int64, error) {
	url := fmt.Sprintf("%s/api/orgs/name/%s", g.baseURL, name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return 0, ErrOrgNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get organisation: %s", resp.Status)
	}
	defer resp.Body.Close()

	var org GetOrgByNameResponse
	err = json.NewDecoder(resp.Body).Decode(&org)
	if err != nil {
		return 0, err
	}

	return org.ID, nil
}

// Create organisation
func (g *GrafanaClient) CreateOrg(name string) (int64, error) {
	orgReq := CreateOrgRequest{
		Name: name,
	}
	orgReqJSON, err := json.Marshal(orgReq)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/orgs", g.baseURL), strings.NewReader(string(orgReqJSON)))
	if err != nil {
		return 0, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusConflict {
		return g.GetOrgByName(name)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to create org: %s", resp.Status)
	}

	defer resp.Body.Close()
	var org CreateOrgResponse
	err = json.NewDecoder(resp.Body).Decode(&org)
	if err != nil {
		return 0, err
	}

	return org.OrgId, nil
}

// Get user by email
func (g *GrafanaClient) GetUserByEmail(email string) (int64, error) {
	url := fmt.Sprintf("%s/api/users/lookup?loginOrEmail=%s", g.baseURL, email)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return 0, ErrUserNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get user: %s", resp.Status)
	}

	defer resp.Body.Close()
	var user GetUserByEmailResponse
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		return 0, err
	}

	return user.ID, nil
}

// Create user
func (g *GrafanaClient) CreateUser(email, name, password string, orgId int64) (int64, error) {
	userReq := CreateUserRequest{
		Email:    email,
		Name:     name,
		Password: password,
		OrgId:    orgId,
		Login:    "user",
	}
	body, err := json.Marshal(userReq)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/admin/users", g.baseURL), strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusConflict {
		return g.GetUserByEmail(name)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to create user: %s", resp.Status)
	}

	defer resp.Body.Close()
	var user CreateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		return 0, err
	}

	return user.ID, nil
}

// Check if user is in organisation
func (g *GrafanaClient) UserInOrg(email string, orgID int64) (bool, error) {
	url := fmt.Sprintf("%s/api/orgs/%d/users", g.baseURL, orgID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusConflict {
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to check if user is in org: %s", resp.Status)
	}

	defer resp.Body.Close()
	var users []UserInOrgResponse
	err = json.NewDecoder(resp.Body).Decode(&users)
	if err != nil {
		return false, err
	}

	for _, user := range users {
		if user.Email == email {
			return true, nil
		}
	}
	return false, nil
}

// Add user to organisation
func (g *GrafanaClient) AddUserToOrg(email string, orgID int64, role string) error {
	orgReq := AddUserToOrgRequest{
		LoginOrEmail: email,
		Role:         role,
	}
	body, err := json.Marshal(orgReq)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/orgs/%d/users", g.baseURL, orgID)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add user to org: %s", resp.Status)
	}

	return nil
}

// Switch users organizational context
func (g *GrafanaClient) SwitchUserContext(userId, orgId int64) error {
	url := fmt.Sprintf("%s/api/users/%d/using/%d", g.baseURL, userId, orgId)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to switch user context: %s", resp.Status)
	}

	return nil
}

// Update a user's role in an organization
func (g *GrafanaClient) UpdateUserOrgRole(userId, orgId int64, role string) error {
	url := fmt.Sprintf("%s/api/orgs/%d/users/%d", g.baseURL, orgId, userId)

	orgReq := UpdateUserOrgRole{
		Role: role,
	}
	body, err := json.Marshal(orgReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", g.basicAuthEnc))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update user org role: %s", resp.Status)
	}

	return nil
}
