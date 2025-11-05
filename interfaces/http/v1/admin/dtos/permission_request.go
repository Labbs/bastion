package dtos

type GrantPermissionRequest struct {
	UserId     string `json:"user_id" validate:"required"`
	ResourceId string `json:"resource_id" validate:"required"`
	Permission string `json:"permission" validate:"required,oneof=read write admin"`
}

type RevokePermissionRequest struct {
	UserId     string `json:"user_id" validate:"required"`
	ResourceId string `json:"resource_id" validate:"required"`
}

type GrantGroupPermissionRequest struct {
	GroupId    string `json:"group_id" validate:"required"`
	ResourceId string `json:"resource_id" validate:"required"`
	Permission string `json:"permission" validate:"required,oneof=read write admin"`
}

type RevokeGroupPermissionRequest struct {
	GroupId    string `json:"group_id" validate:"required"`
	ResourceId string `json:"resource_id" validate:"required"`
}

