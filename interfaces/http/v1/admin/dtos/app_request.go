package dtos

type CreateAppRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
	Url         string `json:"url" validate:"required,url"`
	Icon        string `json:"icon"`
}

type UpdateAppRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Url         string `json:"url"`
	Icon        string `json:"icon"`
	Active      bool   `json:"active"`
}

