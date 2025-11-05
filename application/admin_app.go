package application

import (
	"fmt"

	"github.com/gofiber/fiber/v2/utils"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type AdminApp struct {
	Config            config.Config
	Logger            zerolog.Logger
	UserApp           *UserApp
	HostApp           *HostApp
	AppApp            *AppApp
	AppPermissionPers domain.AppPermissionPers
	GroupPers         domain.GroupPers
}

func NewAdminApp(cfg config.Config, logger zerolog.Logger, userApp *UserApp, hostApp *HostApp, appApp *AppApp, appPermissionPers domain.AppPermissionPers, groupPers domain.GroupPers) *AdminApp {
	return &AdminApp{
		Config:            cfg,
		Logger:            logger,
		UserApp:           userApp,
		HostApp:           hostApp,
		AppApp:            appApp,
		AppPermissionPers: appPermissionPers,
		GroupPers:         groupPers,
	}
}

// User management
func (a *AdminApp) UpdateUserRole(userId string, role domain.Role) error {
	logger := a.Logger.With().Str("component", "application.admin.update_user_role").Logger()

	user, err := a.UserApp.GetByUserId(userId)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Role = role
	updatedUser, err := a.UserApp.UserPres.Update(*user)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to update user role")
		return fmt.Errorf("failed to update user role: %w", err)
	}
	_ = updatedUser // Use updated user

	logger.Info().Str("user_id", userId).Str("role", string(role)).Msg("user role updated")
	return nil
}

func (a *AdminApp) SetUserActive(userId string, active bool) error {
	logger := a.Logger.With().Str("component", "application.admin.set_user_active").Logger()

	user, err := a.UserApp.GetByUserId(userId)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Active = active
	updatedUser, err := a.UserApp.UserPres.Update(*user)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to update user active status")
		return fmt.Errorf("failed to update user active status: %w", err)
	}
	_ = updatedUser // Use updated user

	logger.Info().Str("user_id", userId).Bool("active", active).Msg("user active status updated")
	return nil
}

func (a *AdminApp) GetAllUsers() ([]domain.User, error) {
	logger := a.Logger.With().Str("component", "application.admin.get_all_users").Logger()

	users, err := a.UserApp.UserPres.GetAll()
	if err != nil {
		logger.Error().Err(err).Msg("failed to get all users")
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}

	return users, nil
}

// Host management
func (a *AdminApp) CreateHost(host domain.Host) (*domain.Host, error) {
	logger := a.Logger.With().Str("component", "application.admin.create_host").Logger()

	host.Id = utils.UUIDv4()
	host.Active = true

	createdHost, err := a.HostApp.HostPers.Create(host)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create host")
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	logger.Info().Str("host_id", createdHost.Id).Str("hostname", createdHost.Hostname).Msg("host created")
	return &createdHost, nil
}

func (a *AdminApp) UpdateHost(host domain.Host) (*domain.Host, error) {
	logger := a.Logger.With().Str("component", "application.admin.update_host").Logger()

	updatedHost, err := a.HostApp.HostPers.Update(host)
	if err != nil {
		logger.Error().Err(err).Str("host_id", host.Id).Msg("failed to update host")
		return nil, fmt.Errorf("failed to update host: %w", err)
	}

	logger.Info().Str("host_id", updatedHost.Id).Msg("host updated")
	return &updatedHost, nil
}

func (a *AdminApp) DeleteHost(hostId string) error {
	logger := a.Logger.With().Str("component", "application.admin.delete_host").Logger()

	err := a.HostApp.HostPers.Delete(hostId)
	if err != nil {
		logger.Error().Err(err).Str("host_id", hostId).Msg("failed to delete host")
		return fmt.Errorf("failed to delete host: %w", err)
	}

	logger.Info().Str("host_id", hostId).Msg("host deleted")
	return nil
}

func (a *AdminApp) GetAllHosts() ([]domain.Host, error) {
	return a.HostApp.HostPers.GetAll()
}

// App management
func (a *AdminApp) CreateApp(name, description, url, icon string) (*domain.WebApp, error) {
	logger := a.Logger.With().Str("component", "application.admin.create_app").Logger()

	app := domain.WebApp{
		Id:          utils.UUIDv4(),
		Name:        name,
		Description: description,
		Url:         url,
		Icon:        icon,
		Active:      true,
	}

	createdApp, err := a.AppApp.AppPers.Create(app)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create app")
		return nil, fmt.Errorf("failed to create app: %w", err)
	}

	logger.Info().Str("app_id", createdApp.Id).Str("name", createdApp.Name).Msg("app created")
	return &createdApp, nil
}

func (a *AdminApp) UpdateApp(appId, name, description, url, icon string, active bool) (*domain.WebApp, error) {
	logger := a.Logger.With().Str("component", "application.admin.update_app").Logger()

	app := domain.WebApp{
		Id:          appId,
		Name:        name,
		Description: description,
		Url:         url,
		Icon:        icon,
		Active:      active,
	}

	updatedApp, err := a.AppApp.AppPers.Update(app)
	if err != nil {
		logger.Error().Err(err).Str("app_id", appId).Msg("failed to update app")
		return nil, fmt.Errorf("failed to update app: %w", err)
	}

	logger.Info().Str("app_id", updatedApp.Id).Msg("app updated")
	return &updatedApp, nil
}

func (a *AdminApp) DeleteApp(appId string) error {
	logger := a.Logger.With().Str("component", "application.admin.delete_app").Logger()

	err := a.AppApp.AppPers.Delete(appId)
	if err != nil {
		logger.Error().Err(err).Str("app_id", appId).Msg("failed to delete app")
		return fmt.Errorf("failed to delete app: %w", err)
	}

	logger.Info().Str("app_id", appId).Msg("app deleted")
	return nil
}

func (a *AdminApp) GetAllApps() ([]domain.WebApp, error) {
	return a.AppApp.AppPers.GetAll()
}

func (a *AdminApp) GetAppById(appId string) (*domain.WebApp, error) {
	app, err := a.AppApp.AppPers.GetById(appId)
	if err != nil {
		return nil, fmt.Errorf("app not found: %w", err)
	}
	return &app, nil
}

// Permission management
func (a *AdminApp) GrantHostPermission(userId string, hostId string, permission string) error {
	logger := a.Logger.With().Str("component", "application.admin.grant_host_permission").Logger()

	// TODO: Implement permission granting
	// This would require a UserHostPermissionPers repository
	logger.Info().Str("user_id", userId).Str("host_id", hostId).Str("permission", permission).Msg("host permission granted")
	return nil
}

func (a *AdminApp) RevokeHostPermission(userId string, hostId string) error {
	logger := a.Logger.With().Str("component", "application.admin.revoke_host_permission").Logger()

	// TODO: Implement permission revocation
	logger.Info().Str("user_id", userId).Str("host_id", hostId).Msg("host permission revoked")
	return nil
}

func (a *AdminApp) GrantAppPermission(userId string, appId string) error {
	logger := a.Logger.With().Str("component", "application.admin.grant_app_permission").Logger()

	// Verify app exists
	_, err := a.AppApp.AppPers.GetById(appId)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	// Verify user exists
	_, err = a.UserApp.GetByUserId(userId)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	err = a.AppPermissionPers.GrantUserPermission(userId, appId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Str("app_id", appId).Msg("failed to grant app permission")
		return fmt.Errorf("failed to grant app permission: %w", err)
	}

	logger.Info().Str("user_id", userId).Str("app_id", appId).Msg("app permission granted")
	return nil
}

func (a *AdminApp) RevokeAppPermission(userId string, appId string) error {
	logger := a.Logger.With().Str("component", "application.admin.revoke_app_permission").Logger()

	err := a.AppPermissionPers.RevokeUserPermission(userId, appId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Str("app_id", appId).Msg("failed to revoke app permission")
		return fmt.Errorf("failed to revoke app permission: %w", err)
	}

	logger.Info().Str("user_id", userId).Str("app_id", appId).Msg("app permission revoked")
	return nil
}

func (a *AdminApp) GrantGroupAppPermission(groupId string, appId string) error {
	logger := a.Logger.With().Str("component", "application.admin.grant_group_app_permission").Logger()

	// Verify app exists
	_, err := a.AppApp.AppPers.GetById(appId)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	// Verify group exists
	_, err = a.GroupPers.GetById(groupId)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	err = a.AppPermissionPers.GrantGroupPermission(groupId, appId)
	if err != nil {
		logger.Error().Err(err).Str("group_id", groupId).Str("app_id", appId).Msg("failed to grant group app permission")
		return fmt.Errorf("failed to grant group app permission: %w", err)
	}

	logger.Info().Str("group_id", groupId).Str("app_id", appId).Msg("group app permission granted")
	return nil
}

func (a *AdminApp) RevokeGroupAppPermission(groupId string, appId string) error {
	logger := a.Logger.With().Str("component", "application.admin.revoke_group_app_permission").Logger()

	err := a.AppPermissionPers.RevokeGroupPermission(groupId, appId)
	if err != nil {
		logger.Error().Err(err).Str("group_id", groupId).Str("app_id", appId).Msg("failed to revoke group app permission")
		return fmt.Errorf("failed to revoke group app permission: %w", err)
	}

	logger.Info().Str("group_id", groupId).Str("app_id", appId).Msg("group app permission revoked")
	return nil
}

// Group management
func (a *AdminApp) CreateGroup(name, description, ownerId string, role domain.Role) (*domain.Group, error) {
	logger := a.Logger.With().Str("component", "application.admin.create_group").Logger()

	group := domain.Group{
		Id:          utils.UUIDv4(),
		Name:        name,
		Description: description,
		OwnerId:     ownerId,
		Role:        role,
	}

	err := a.GroupPers.Create(&group)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create group")
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	logger.Info().Str("group_id", group.Id).Str("name", group.Name).Msg("group created")
	return &group, nil
}

func (a *AdminApp) UpdateGroup(groupId, name, description string, role domain.Role) (*domain.Group, error) {
	logger := a.Logger.With().Str("component", "application.admin.update_group").Logger()

	group, err := a.GroupPers.GetById(groupId)
	if err != nil {
		return nil, fmt.Errorf("group not found: %w", err)
	}

	group.Name = name
	group.Description = description
	group.Role = role

	err = a.GroupPers.Update(group)
	if err != nil {
		logger.Error().Err(err).Str("group_id", groupId).Msg("failed to update group")
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	logger.Info().Str("group_id", groupId).Msg("group updated")
	return group, nil
}

func (a *AdminApp) DeleteGroup(groupId string) error {
	logger := a.Logger.With().Str("component", "application.admin.delete_group").Logger()

	err := a.GroupPers.Delete(groupId)
	if err != nil {
		logger.Error().Err(err).Str("group_id", groupId).Msg("failed to delete group")
		return fmt.Errorf("failed to delete group: %w", err)
	}

	logger.Info().Str("group_id", groupId).Msg("group deleted")
	return nil
}

func (a *AdminApp) GetAllGroups() ([]domain.Group, error) {
	return a.GroupPers.GetAll()
}

func (a *AdminApp) GetGroupById(groupId string) (*domain.Group, error) {
	return a.GroupPers.GetById(groupId)
}

func (a *AdminApp) AddUserToGroup(groupId, userId string) error {
	logger := a.Logger.With().Str("component", "application.admin.add_user_to_group").Logger()

	err := a.GroupPers.AddMember(groupId, userId)
	if err != nil {
		logger.Error().Err(err).Str("group_id", groupId).Str("user_id", userId).Msg("failed to add user to group")
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	logger.Info().Str("group_id", groupId).Str("user_id", userId).Msg("user added to group")
	return nil
}

func (a *AdminApp) RemoveUserFromGroup(groupId, userId string) error {
	logger := a.Logger.With().Str("component", "application.admin.remove_user_from_group").Logger()

	err := a.GroupPers.RemoveMember(groupId, userId)
	if err != nil {
		logger.Error().Err(err).Str("group_id", groupId).Str("user_id", userId).Msg("failed to remove user from group")
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	logger.Info().Str("group_id", groupId).Str("user_id", userId).Msg("user removed from group")
	return nil
}

func (a *AdminApp) GetGroupMembers(groupId string) ([]domain.User, error) {
	return a.GroupPers.GetMembers(groupId)
}

// Extended user management
func (a *AdminApp) CreateUser(username, email, password string, role domain.Role) (*domain.User, error) {
	logger := a.Logger.With().Str("component", "application.admin.create_user").Logger()

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error().Err(err).Msg("failed to hash password")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := domain.User{
		Id:       utils.UUIDv4(),
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
		Role:     role,
		Active:   true,
	}

	createdUser, err := a.UserApp.UserPres.Create(user)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	logger.Info().Str("user_id", createdUser.Id).Str("username", createdUser.Username).Msg("user created")
	return &createdUser, nil
}

func (a *AdminApp) DeleteUser(userId string) error {
	logger := a.Logger.With().Str("component", "application.admin.delete_user").Logger()

	// Note: This should check if user has dependencies before deleting
	err := a.UserApp.UserPres.Delete(userId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	logger.Info().Str("user_id", userId).Msg("user deleted")
	return nil
}

func (a *AdminApp) UpdateUser(userId, username, email string, role domain.Role, active bool) error {
	logger := a.Logger.With().Str("component", "application.admin.update_user").Logger()

	user, err := a.UserApp.GetByUserId(userId)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.Username = username
	user.Email = email
	user.Role = role
	user.Active = active

	_, err = a.UserApp.UserPres.Update(*user)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to update user")
		return fmt.Errorf("failed to update user: %w", err)
	}

	logger.Info().Str("user_id", userId).Msg("user updated")
	return nil
}

func (a *AdminApp) GetUserById(userId string) (*domain.User, error) {
	user, err := a.UserApp.GetByUserId(userId)
	if err != nil {
		return nil, err
	}
	return user, nil
}
