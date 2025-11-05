package http

import (
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/logger/zerolog"
	"github.com/labbs/bastion/infrastructure/ui"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	fiberoapi "github.com/labbs/fiber-oapi"
	z "github.com/rs/zerolog"
)

type Config struct {
	Fiber     *fiber.App
	FiberOapi *fiberoapi.OApiApp
}

// Configure sets up the HTTP server (fiber) with the provided configuration and logger.
// The FiberOapi instance is also configured for OpenAPI support and exposed documentation.
// Will return an error if the server cannot be created (fatal)
func Configure(_cfg config.Config, logger z.Logger, session application.SessionApp, enableIU bool) (Config, error) {
	var c Config
	fiberConfig := fiber.Config{
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		DisableStartupMessage: true,
		Views:                 ui.InitEngine(),
		// Augmenter significativement les limites pour supporter les URLs très longues de Google
		// ReadBufferSize contrôle la taille du buffer de lecture (inclut les headers + URI)
		// On accepte des buffers jusqu'à 128KB (par défaut c'est 4KB)
		ReadBufferSize: 131072, // 128KB
		// Augmenter aussi la taille max du body pour les requêtes POST
		BodyLimit: 10 * 1024 * 1024, // 10MB
		// IMPORTANT: StreamRequestBody permet de contourner les limites de FastHTTP sur les URIs
		// En activant cela, FastHTTP ne stocke pas l'URI entière en mémoire d'un coup
		// Cela résout le problème des URLs très longues de Google (> 3000 chars)
		StreamRequestBody: true,
	}

	r := fiber.New(fiberConfig)

	if _cfg.Server.HttpLogs {
		r.Use(zerolog.HTTPLogger(logger))
	}

	r.Use(recover.New())
	r.Use(cors.New())
	r.Use(compress.New())
	r.Use(requestid.New())

	oapiConfig := fiberoapi.Config{
		EnableValidation:    true,
		EnableOpenAPIDocs:   true,
		OpenAPIDocsPath:     "/documentation",
		OpenAPIJSONPath:     "/api-spec.json",
		OpenAPIYamlPath:     "/api-spec.yaml",
		AuthService:         &session,
		EnableAuthorization: true,
		SecuritySchemes: map[string]fiberoapi.SecurityScheme{
			"bearerAuth": {
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
				Description:  "JWT Bearer token",
			},
		},
		DefaultSecurity: []map[string][]string{
			{"bearerAuth": {}},
		},
	}

	c.FiberOapi = fiberoapi.New(r, oapiConfig)
	c.Fiber = r

	return c, nil
}
