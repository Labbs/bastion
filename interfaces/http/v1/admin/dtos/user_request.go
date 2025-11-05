package dtos

type UpdateUserRequest struct {
	Role   string `json:"role" validate:"omitempty,oneof=admin user guest"`
	Active bool   `json:"active"`
}

type UserResponse struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
}

