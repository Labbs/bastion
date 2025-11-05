package dtos

type CreateHostRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
	Hostname    string `json:"hostname" validate:"required"`
	Port        int    `json:"port" validate:"required,min=1,max=65535"`
	Username    string `json:"username" validate:"required"`
	AuthMethod  string `json:"auth_method" validate:"required,oneof=password key both"`
	Password    string `json:"password,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
}

type UpdateHostRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthMethod  string `json:"auth_method"`
	Password    string `json:"password,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	Active      bool   `json:"active"`
}

type HostResponse struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthMethod  string `json:"auth_method"`
	Active      bool   `json:"active"`
}

