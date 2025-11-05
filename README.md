# Bastion

**Bastion** is a comprehensive Identity and Access Management (IAM) system that provides secure access to SSH hosts and web applications through a unified interface. It acts as a centralized gateway for managing user authentication, authorization, and access control.

## Features

### 🔐 Authentication & Authorization
- User registration and authentication with JWT tokens
- Role-based access control (RBAC)
- Group management for organizing users
- Session management with automatic cleanup
- Admin interface for user and permission management

### 🖥️ SSH Bastion Host
- Secure SSH proxy server for accessing remote hosts
- Public key and password authentication
- SSH session recording and auditing
- Interactive host selection menu
- Dynamic host management

### 🌐 Web Application Proxy
- HTTP/HTTPS proxy for web applications
- Automatic URL rewriting for seamless proxying
- CORS handling for cross-origin requests
- JavaScript injection for `fetch()` and `XMLHttpRequest` interception
- Support for complex web applications (e.g., Google, Twitch)
- Cookie and session forwarding
- Handles long URLs and large request bodies

### 📊 Administration
- Web-based admin interface
- User and group management
- Application and host configuration
- Permission management
- Session monitoring

## Architecture

Bastion follows a clean architecture pattern:

```
├── cmd/                    # Application entry point
├── domain/                 # Domain models and entities
├── application/            # Business logic and use cases
├── infrastructure/         # Infrastructure implementations
│   ├── config/            # Configuration management
│   ├── database/          # Database connection (GORM)
│   ├── http/              # HTTP server (Fiber)
│   ├── logger/            # Logging (Zerolog)
│   ├── migration/         # Database migrations (Goose)
│   └── persistence/       # Data access layer
└── interfaces/            # External interfaces
    ├── cli/               # CLI commands
    ├── http/              # HTTP handlers and routes
    └── ssh/               # SSH server implementation
```

## Requirements

- **Go**: 1.25.1 or higher
- **Database**: PostgreSQL or SQLite
- **Network**: Access to target SSH hosts and web applications

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/labbs/bastion.git
cd bastion
```

2. Build the application:
```bash
go build -o bin/bastion ./cmd
```

3. Run database migrations:
```bash
./bin/bastion migration up
```

4. Start the HTTP server:
```bash
./bin/bastion server
```

5. (Optional) Start the SSH server:
```bash
./bin/bastion ssh
```

### Docker

```bash
docker build -t bastion .
docker run -p 8080:8080 -v $(pwd)/database.sqlite:/app/database.sqlite bastion
```

## Configuration

Bastion uses YAML configuration files. Create a `config.yaml` file:

```yaml
http:
  port: 8080
  logs: true

logger:
  level: info
  pretty: false

database:
  dialect: postgres  # or sqlite
  dsn: postgres://user:password@localhost/bastion?sslmode=disable

ssh:
  port: 2222
  host_key: /path/to/host_key

session:
  secret: your-secret-key-here
  expiration: 24h

auth:
  registration_enabled: true
  jwt_secret: your-jwt-secret-here

registration:
  enabled: true
```

Configuration can also be provided via command-line flags. Run `./bin/bastion server --help` for available options.

## Usage

### Starting Services

**HTTP Server** (Web UI and API):
```bash
./bin/bastion server --http.port 8080
```

**SSH Server**:
```bash
./bin/bastion ssh --ssh.port 2222
```

### Web Interface

1. Access the web interface at `http://localhost:8080`
2. Register a new account (if registration is enabled)
3. Log in with your credentials
4. Access your assigned applications and hosts

### SSH Access

1. Connect to the SSH server:
```bash
ssh -p 2222 user@bastion-host
```

2. Select a host from the interactive menu
3. The session will be proxied to the selected host

### Admin Interface

1. Access `/admin` after logging in as an admin user
2. Manage users, groups, applications, and hosts
3. Configure permissions and access controls

## API

Bastion provides a RESTful API for programmatic access:

- **Authentication**: `/api/v1/auth/login`, `/api/v1/auth/register`
- **Applications**: `/api/v1/app/apps`
- **User Profile**: `/api/v1/user/profile`
- **Admin**: `/api/v1/admin/*`

API documentation is available via OpenAPI/Swagger when enabled.

## Development

### Prerequisites

- Go 1.25.1+
- Make (optional, for convenience)

### Project Structure

- `cmd/`: Application entry points
- `domain/`: Core domain models
- `application/`: Business logic layer
- `infrastructure/`: External dependencies (database, HTTP, etc.)
- `interfaces/`: Adapters for external interfaces

### Running Tests

```bash
go test ./...
```

### Database Migrations

Create a new migration:
```bash
./bin/bastion migration create migration_name
```

Run migrations:
```bash
./bin/bastion migration up
```

Rollback migrations:
```bash
./bin/bastion migration down
```

### Building

```bash
# Build for current platform
go build -o bin/bastion ./cmd

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o bin/bastion-linux ./cmd

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o bin/bastion.exe ./cmd
```

## Web Application Proxy Details

The web application proxy is designed to handle complex modern web applications:

- **Automatic URL Rewriting**: All URLs in HTML, CSS, and JavaScript are automatically rewritten to go through the proxy
- **JavaScript Interception**: `fetch()` and `XMLHttpRequest` are patched to route requests through the proxy
- **CORS Handling**: Proxied requests handle CORS automatically
- **Large URL Support**: Handles URLs up to 16KB in length
- **Dynamic Content**: Intercepts dynamically created `<script>` and `<link>` tags

## Security Considerations

- All user passwords are hashed before storage
- JWT tokens are used for authentication
- SSH sessions can be recorded for auditing
- Access control is enforced at both application and host levels
- Admin operations require elevated privileges

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions, please open an issue on GitHub.
