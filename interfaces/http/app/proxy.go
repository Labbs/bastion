package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/rs/zerolog"
	"golang.org/x/net/html"
)

type ProxyController struct {
	Config     config.Config
	Logger     zerolog.Logger
	AppApp     *application.AppApp
	SessionApp *application.SessionApp
}

func SetupProxyRouter(deps infrastructure.Deps) {
	deps.Logger.Info().Str("component", "http.router.app.proxy").Msg("Setting up app proxy routes")

	proxyCtrl := ProxyController{
		Config:     deps.Config,
		Logger:     deps.Logger,
		AppApp:     deps.AppApp,
		SessionApp: deps.SessionApp,
	}

	// Proxy route for apps
	deps.Http.Fiber.All("/apps/:id/proxy/*", proxyCtrl.ProxyApp)
}

func (ctrl *ProxyController) ProxyApp(ctx *fiber.Ctx) error {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.app.proxy").Logger()

	appId := ctx.Params("id")
	proxyPath := ctx.Params("*")

	// Nettoyer le proxyPath s'il commence par "/" (TrimPrefix est idempotent)
	proxyPath = strings.TrimPrefix(proxyPath, "/")

	// Log de debug pour voir la taille de l'URI complète reçue
	fullRequestURI := string(ctx.Request().RequestURI())
	logger.Debug().
		Str("proxy_path", proxyPath).
		Str("original_path", ctx.Path()).
		Int("full_uri_length", len(fullRequestURI)).
		Str("full_uri_preview", func() string {
			if len(fullRequestURI) > 200 {
				return fullRequestURI[:200] + "... (truncated)"
			}
			return fullRequestURI
		}()).
		Msg("proxy request received")

	// Extract token from header or cookie
	var token string
	authHeader := ctx.Get("Authorization")
	if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	// If no token in header, check cookie
	if token == "" {
		token = ctx.Cookies("token")
	}

	// If still no token, return unauthorized
	if token == "" {
		logger.Debug().Msg("no authentication token found for proxy")
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	// Validate token
	authCtx, err := ctrl.SessionApp.ValidateToken(token)
	if err != nil {
		logger.Error().Err(err).Msg("failed to validate token")
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	// Verify user exists and is active
	user, err := ctrl.SessionApp.UserApp.GetByUserId(authCtx.UserID)
	if err != nil || !user.Active {
		logger.Debug().Str("user_id", authCtx.UserID).Msg("user not found or inactive")
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	// Verify user has access to this app
	app, err := ctrl.AppApp.ConnectToApp(authCtx.UserID, appId)
	if err != nil {
		logger.Error().Err(err).Str("app_id", appId).Msg("user does not have access to app")
		return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Access denied",
		})
	}

	// Parse base URL for later use
	baseURLParsed, err := url.Parse(app.Url)
	if err != nil {
		logger.Error().Err(err).Str("app_url", app.Url).Msg("failed to parse app URL")
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid app URL",
		})
	}

	// Lire le body AVANT de construire l'URL pour éviter de le perdre
	bodyBytes := ctx.Body()

	// Check if this is a request for an external resource
	var targetURL string
	externalURL := ctx.Query("url")
	if externalURL != "" {
		// This is a proxied external resource
		decodedURL, err := url.QueryUnescape(externalURL)
		if err == nil {
			targetURL = decodedURL
		} else {
			targetURL = externalURL
		}
		// Pour les requêtes POST vers external, on doit s'assurer que le body est correctement lu
		// Le body a déjà été lu plus haut, donc c'est bon
	} else {
		// Build target URL from app URL
		baseURL, err := url.Parse(app.Url)
		if err != nil {
			logger.Error().Err(err).Str("app_url", app.Url).Msg("failed to parse app URL")
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Invalid app URL",
			})
		}

		// Construire le chemin de manière plus robuste
		if proxyPath != "" {
			// Si le proxyPath commence déjà par /, on l'utilise tel quel
			// Sinon, on l'ajoute après le chemin de base
			if strings.HasPrefix(proxyPath, "/") {
				baseURL.Path = strings.TrimSuffix(baseURL.Path, "/") + proxyPath
			} else {
				if strings.HasSuffix(baseURL.Path, "/") {
					baseURL.Path = baseURL.Path + proxyPath
				} else {
					baseURL.Path = baseURL.Path + "/" + proxyPath
				}
			}
		}

		// Add query string if present (but not if it's the external URL param)
		// IMPORTANT: On utilise la query string brute (RawQuery) pour éviter le double encodage
		// Si on utilise Query() puis Encode(), les valeurs déjà encodées sont ré-encodées
		originalQueryString := string(ctx.Request().URI().QueryString())

		if len(originalQueryString) > 0 {
			logger.Debug().
				Str("original_query_string_preview", func() string {
					if len(originalQueryString) > 200 {
						return originalQueryString[:200] + "..."
					}
					return originalQueryString
				}()).
				Int("original_query_length", len(originalQueryString)).
				Msg("processing query parameters")

			// Utiliser directement la query string brute au lieu de la parser et ré-encoder
			// Cela évite le double encodage des caractères spéciaux
			baseURL.RawQuery = originalQueryString
		}

		targetURL = baseURL.String()
	}

	// Log plus détaillé pour le debugging
	urlPreview := targetURL
	if len(targetURL) > 200 {
		urlPreview = targetURL[:200] + "..."
	}
	logger.Info().
		Str("target_url_preview", urlPreview).
		Str("method", ctx.Method()).
		Int("body_size", len(bodyBytes)).
		Int("target_url_length", len(targetURL)).
		Int("received_uri_length", len(string(ctx.Request().RequestURI()))).
		Str("proxy_path_preview", func() string {
			if len(proxyPath) > 100 {
				return proxyPath[:100] + "... (truncated)"
			}
			return proxyPath
		}()).
		Msg("proxying request to target")

	// Vérifier que l'URL n'est pas trop longue (limite de sécurité)
	// Augmenter la limite à 16KB pour les URLs très longues de Google
	if len(targetURL) > 16384 {
		logger.Error().Int("url_length", len(targetURL)).Msg("URL too long")
		return ctx.Status(fiber.StatusRequestURITooLong).JSON(fiber.Map{
			"error": "URL too long",
		})
	}

	// Create request to target app
	// Préserver le body pour les requêtes POST/PUT/PATCH
	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(ctx.Method(), targetURL, bodyReader)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create proxy request")
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create proxy request",
		})
	}

	// Copy only essential headers (comme Warpgate, on ne copie que les headers nécessaires)
	// Cette approche évite les erreurs 431 dues aux headers trop longs
	headersToForward := map[string]string{
		"accept":           ctx.Get("Accept"),
		"accept-language":  ctx.Get("Accept-Language"),
		"accept-encoding":  ctx.Get("Accept-Encoding"),
		"user-agent":       ctx.Get("User-Agent"),
		"referer":          ctx.Get("Referer"),
		"origin":           ctx.Get("Origin"),
		"x-requested-with": ctx.Get("X-Requested-With"),
	}

	for headerName, headerValue := range headersToForward {
		if headerValue != "" && len(headerValue) < 4096 {
			req.Header.Set(headerName, headerValue)
		}
	}

	// Copy Content-Type for POST/PUT/PATCH requests
	if len(bodyBytes) > 0 {
		if contentType := ctx.Get("Content-Type"); contentType != "" && len(contentType) < 512 {
			req.Header.Set("Content-Type", contentType)
		}
	}

	// Copy Authorization header if present (but limit its size)
	if authHeader := ctx.Get("Authorization"); authHeader != "" && len(authHeader) < 2048 {
		req.Header.Set("Authorization", authHeader)
	}

	// Set Content-Length for POST/PUT/PATCH requests
	if len(bodyBytes) > 0 && (ctx.Method() == "POST" || ctx.Method() == "PUT" || ctx.Method() == "PATCH") {
		req.ContentLength = int64(len(bodyBytes))
	}

	// Set the correct Host header for the target
	req.Header.Set("Host", baseURLParsed.Host)

	// Remove Accept-Encoding to prevent compression
	// We'll handle decompression manually if needed, but for simplicity, let's avoid compression
	req.Header.Del("Accept-Encoding")

	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error().Err(err).Str("target_url", targetURL).Msg("failed to execute proxy request")
		return ctx.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Failed to connect to target app",
		})
	}
	defer resp.Body.Close()

	// Log si on reçoit une erreur HTTP
	if resp.StatusCode >= 400 {
		logger.Warn().
			Int("status_code", resp.StatusCode).
			Str("status", resp.Status).
			Str("target_url_preview", func() string {
				if len(targetURL) > 200 {
					return targetURL[:200] + "..."
				}
				return targetURL
			}()).
			Msg("target server returned error status")
	}

	// Copy response headers (excluding some that shouldn't be forwarded)
	for key, values := range resp.Header {
		keyLower := strings.ToLower(key)
		// Skip headers that shouldn't be forwarded
		if keyLower == "connection" || keyLower == "transfer-encoding" || keyLower == "content-length" {
			continue
		}
		// Remove Content-Encoding because the HTTP client already decompressed the body
		// If we keep it, the browser will try to decompress again and fail with ERR_CONTENT_DECODING_FAILED
		if keyLower == "content-encoding" {
			continue
		}
		// Remove security headers that might block iframe
		if keyLower == "x-frame-options" ||
			keyLower == "content-security-policy" ||
			keyLower == "content-security-policy-report-only" {
			continue
		}

		// Réécrire les domaines dans les cookies
		if keyLower == "set-cookie" {
			for _, value := range values {
				rewrittenCookie := ctrl.rewriteCookieDomain(value, baseURLParsed.Host, ctx.Hostname())
				ctx.Response().Header.Add(key, rewrittenCookie)
			}
			continue
		}

		for _, value := range values {
			ctx.Response().Header.Add(key, value)
		}
	}

	// Add CORS headers for iframe
	ctx.Response().Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response().Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	ctx.Response().Header.Set("Access-Control-Allow-Headers", "*")

	// Set status code
	ctx.Status(resp.StatusCode)

	// Copy response body
	// IMPORTANT: Go's http.Client automatically decompresses if Content-Encoding header is present
	// But we need to read the body BEFORE Fiber's compression middleware tries to compress it
	// We've already removed Content-Encoding from headers above, so the body should be decompressed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read proxy response body")
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to read response",
		})
	}

	// Réécriture d'URLs pour HTML, CSS et JavaScript
	contentType := resp.Header.Get("Content-Type")
	if len(body) > 0 {
		if strings.Contains(contentType, "text/html") {
			body = ctrl.rewriteHTMLURLs(body, appId, app.Url, ctx)
		} else if strings.Contains(contentType, "text/css") || strings.Contains(contentType, "text/javascript") || strings.Contains(contentType, "application/javascript") {
			body = ctrl.rewriteTextURLs(body, appId, app.Url, ctx)
		}
	}

	return ctx.Send(body)
}

// rewriteHTMLURLs réécrit les URLs dans le HTML en utilisant le parser HTML de golang.org/x/net/html
func (ctrl *ProxyController) rewriteHTMLURLs(content []byte, appId, baseURL string, ctx *fiber.Ctx) []byte {
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return content
	}

	// Get the proxy base URL
	proxyBase := fmt.Sprintf("%s://%s/apps/%s/proxy",
		ctx.Protocol(), ctx.Hostname(), appId)

	// Parse HTML
	doc, err := html.Parse(bytes.NewReader(content))
	if err != nil {
		// Si le parsing échoue, retourner le contenu original
		return content
	}

	// Injecter le patch JavaScript EN PREMIER, avant la réécriture des URLs
	// Cela garantit que le patch est actif avant que les scripts chargés ne s'exécutent
	ctrl.injectFetchPatch(doc, appId, ctx)

	// Réécrire les URLs dans le DOM
	ctrl.rewriteNodeURLs(doc, baseURLParsed, proxyBase)

	// Désactiver le Service Worker pour l'instant - les URLs blob ne sont pas supportées
	// Le patch fetch() gère déjà toutes les requêtes
	// ctrl.injectServiceWorker(doc, appId, ctx)

	// Reconstruire le HTML
	var buf bytes.Buffer
	err = html.Render(&buf, doc)
	if err != nil {
		return content
	}

	return buf.Bytes()
}

// rewriteNodeURLs parcourt récursivement les nœuds HTML et réécrit les URLs
func (ctrl *ProxyController) rewriteNodeURLs(n *html.Node, baseURL *url.URL, proxyBase string) {
	if n == nil {
		return
	}

	// Réécrire les attributs contenant des URLs
	if n.Type == html.ElementNode {
		attrsToRewrite := []string{"href", "src", "action", "data-src", "data-href", "background", "cite", "formaction"}

		for i := range n.Attr {
			attr := &n.Attr[i]
			for _, attrName := range attrsToRewrite {
				if attr.Key == attrName {
					attr.Val = ctrl.rewriteURL(attr.Val, baseURL, proxyBase)
					break
				}
			}
		}

		// Réécrire les URLs dans les balises <style>
		if n.Data == "style" {
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				n.FirstChild.Data = ctrl.rewriteCSSURLs(n.FirstChild.Data, baseURL, proxyBase)
			}
		}

		// NE PAS réécrire le JavaScript inline - le patch fetch() gère déjà les requêtes
		// La réécriture JavaScript casse souvent le code valide
		// if n.Data == "script" {
		// 	if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
		// 		// Réécrire les URLs dans le JavaScript
		// 		n.FirstChild.Data = ctrl.rewriteJavaScriptURLs(n.FirstChild.Data, baseURL, proxyBase)
		// 	}
		// }
	}

	// Parcourir récursivement les enfants
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		ctrl.rewriteNodeURLs(c, baseURL, proxyBase)
	}
}

// rewriteURL réécrit une URL pour qu'elle passe par le proxy
// C'est la fonction clé qui permet de proxifier toutes les ressources
func (ctrl *ProxyController) rewriteURL(urlStr string, baseURL *url.URL, proxyBase string) string {
	if urlStr == "" {
		return urlStr
	}

	// Ne pas proxifier les URLs data:, blob:, about:, javascript:, etc.
	if strings.HasPrefix(urlStr, "data:") || strings.HasPrefix(urlStr, "blob:") ||
		strings.HasPrefix(urlStr, "about:") || strings.HasPrefix(urlStr, "javascript:") ||
		strings.HasPrefix(urlStr, "mailto:") || strings.HasPrefix(urlStr, "tel:") {
		return urlStr
	}

	// Pour les URLs absolues, toujours les proxifier via le paramètre ?url=
	// C'est comme ça que Teleport/Pomerium fonctionnent
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") || strings.HasPrefix(urlStr, "//") {
		// Normaliser les URLs protocol-relative (//example.com -> https://example.com)
		if strings.HasPrefix(urlStr, "//") {
			urlStr = "https:" + urlStr
		}

		// Encoder l'URL complète pour passer par le proxy
		// Format: /apps/{id}/proxy/external?url={encoded_url}
		encodedURL := url.QueryEscape(urlStr)
		return proxyBase + "/external?url=" + encodedURL
	}

	// Réécrire les URLs relatives
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	if strings.HasPrefix(urlStr, "/") {
		// Absolute path
		path := urlStr
		if parsedURL.RawQuery != "" {
			path += "?" + parsedURL.RawQuery
		}
		if parsedURL.Fragment != "" {
			path += "#" + parsedURL.Fragment
		}
		return proxyBase + path
	}

	// Relative path
	path := urlStr
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	if parsedURL.Fragment != "" {
		path += "#" + parsedURL.Fragment
	}
	return proxyBase + "/" + path
}

// rewriteTextURLs réécrit les URLs dans du texte (CSS, JavaScript)
func (ctrl *ProxyController) rewriteTextURLs(content []byte, appId, baseURL string, ctx *fiber.Ctx) []byte {
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return content
	}

	proxyBase := fmt.Sprintf("%s://%s/apps/%s/proxy",
		ctx.Protocol(), ctx.Hostname(), appId)

	contentStr := string(content)

	// Réécrire les url() dans CSS
	contentType := ctx.Get("Content-Type")
	if strings.Contains(contentType, "text/css") {
		contentStr = ctrl.rewriteCSSURLs(contentStr, baseURLParsed, proxyBase)
	} else {
		// Réécrire les URLs dans JavaScript
		contentStr = ctrl.rewriteJavaScriptURLs(contentStr, baseURLParsed, proxyBase)
	}

	return []byte(contentStr)
}

// rewriteCSSURLs réécrit les URLs dans le CSS (url(...))
func (ctrl *ProxyController) rewriteCSSURLs(css string, baseURL *url.URL, proxyBase string) string {
	// Pattern pour url() dans CSS
	// On capture url("..."), url('...'), url(...) sans quotes
	urlPattern := `url\s*\(\s*(["']?)([^"')]+)(["']?)\s*\)`

	re := regexp.MustCompile(urlPattern)
	result := re.ReplaceAllStringFunc(css, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			quote1 := submatches[1]
			urlStr := submatches[2]
			quote2 := submatches[3]
			rewritten := ctrl.rewriteURL(urlStr, baseURL, proxyBase)
			return fmt.Sprintf("url(%s%s%s)", quote1, rewritten, quote2)
		}
		return match
	})

	return result
}

// rewriteJavaScriptURLs réécrit les URLs dans le JavaScript
func (ctrl *ProxyController) rewriteJavaScriptURLs(js string, baseURL *url.URL, proxyBase string) string {
	// Patterns pour différents types d'URLs dans JavaScript
	patterns := []struct {
		name    string
		pattern string
	}{
		// fetch, XMLHttpRequest, etc.
		{name: "fetch", pattern: `fetch\s*\(\s*(["'])([^"']+)(["'])\s*(?:,\s*[^)]*)?\s*\)`},
		{name: "fetch with options", pattern: `fetch\s*\(\s*(["'])([^"']+)(["'])\s*,\s*\{[^}]*\}\)`},
		{name: "XMLHttpRequest.open", pattern: `\.open\s*\(\s*(["'])([^"']+)(["'])\s*,`},
		{name: "import", pattern: `import\s+(["'])([^"']+)(["'])`},
		{name: "import()", pattern: `import\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		{name: "require", pattern: `require\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		{name: "location.href", pattern: `location\.href\s*=\s*(["'])([^"']+)(["'])`},
		{name: "location.replace", pattern: `location\.replace\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		{name: "window.open", pattern: `window\.open\s*\(\s*(["'])([^"']+)(["'])`},
		// new Image(), new Audio(), etc.
		{name: "new Image", pattern: `new\s+Image\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		{name: "new Audio", pattern: `new\s+Audio\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		// WebSocket
		{name: "WebSocket", pattern: `new\s+WebSocket\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		// EventSource (Server-Sent Events)
		{name: "EventSource", pattern: `new\s+EventSource\s*\(\s*(["'])([^"']+)(["'])\s*\)`},
		// URLs dans les chaînes de caractères (plus spécifique)
		{name: "string URLs", pattern: `(["'])(https?://[^"']+)(["'])`},
		// Template literals avec URLs
		{name: "template literals", pattern: `\$\{([^}]*https?://[^}]+)\}`},
	}

	result := js
	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			submatches := re.FindStringSubmatch(match)
			if len(submatches) >= 4 {
				prefix := submatches[1]
				urlStr := submatches[2]
				suffix := submatches[3]
				rewritten := ctrl.rewriteURL(urlStr, baseURL, proxyBase)
				return prefix + rewritten + suffix
			}
			return match
		})
	}

	return result
}

// injectServiceWorker injecte le code du Service Worker dans le HTML
func (ctrl *ProxyController) injectServiceWorker(doc *html.Node, appId string, ctx *fiber.Ctx) {
	// Trouver le head ou créer un si nécessaire
	var head *html.Node
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "html" {
			for c2 := c.FirstChild; c2 != nil; c2 = c2.NextSibling {
				if c2.Type == html.ElementNode && c2.Data == "head" {
					head = c2
					break
				}
			}
			if head == nil {
				// Créer un head si nécessaire
				head = &html.Node{
					Type: html.ElementNode,
					Data: "head",
				}
				c.InsertBefore(head, c.FirstChild)
			}
			break
		}
	}

	if head == nil {
		return
	}

	// Créer le script pour enregistrer le Service Worker
	// Échapper correctement le code du Service Worker avec JSON pour éviter les problèmes d'échappement
	swCodeRaw := ctrl.getServiceWorkerCode()
	swCodeJSON, err := json.Marshal(swCodeRaw)
	if err != nil {
		ctrl.Logger.Error().Err(err).Msg("failed to marshal service worker code")
		return
	}

	appIdJSON, _ := json.Marshal(appId)

	swScript := fmt.Sprintf(`(function() {
  if ('serviceWorker' in navigator) {
    const appId = %s;
    const swCode = %s;
    const swCodeWithAppId = swCode.replace(/{APP_ID}/g, appId);
    const blob = new Blob([swCodeWithAppId], { type: 'application/javascript' });
    const swUrl = URL.createObjectURL(blob);
    navigator.serviceWorker.getRegistrations().then(function(registrations) {
      return Promise.all(registrations.map(function(registration) {
        if (registration.scope.includes('/apps/' + appId + '/proxy')) {
          return registration.unregister();
        }
      }));
    }).then(function() {
      return navigator.serviceWorker.register(swUrl, { 
        scope: '/apps/' + appId + '/proxy/' 
      });
    }).then(function(reg) {
      console.log('Service Worker registered for app:', appId, 'scope:', reg.scope);
      if (reg.installing) {
        reg.installing.addEventListener('statechange', function() {
          if (this.state === 'activated') {
            console.log('Service Worker activated');
          }
        });
      } else if (reg.waiting) {
        reg.waiting.postMessage({ type: 'SKIP_WAITING' });
      } else if (reg.active) {
        console.log('Service Worker already active');
      }
      return reg.update();
    }).catch(function(err) {
      console.error('Service Worker registration failed:', err);
    });
  }
})();`, string(appIdJSON), string(swCodeJSON))

	// Créer le nœud script
	scriptNode := &html.Node{
		Type: html.ElementNode,
		Data: "script",
		Attr: []html.Attribute{
			{Key: "type", Val: "text/javascript"},
		},
	}

	textNode := &html.Node{
		Type: html.TextNode,
		Data: swScript,
	}
	scriptNode.AppendChild(textNode)
	head.AppendChild(scriptNode)
}

// injectFetchPatch injecte un patch JavaScript pour intercepter fetch() et XMLHttpRequest
// Cela fonctionne même avant que le Service Worker soit activé
func (ctrl *ProxyController) injectFetchPatch(doc *html.Node, appId string, ctx *fiber.Ctx) {
	var head *html.Node
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "html" {
			for c2 := c.FirstChild; c2 != nil; c2 = c2.NextSibling {
				if c2.Type == html.ElementNode && c2.Data == "head" {
					head = c2
					break
				}
			}
			break
		}
	}

	if head == nil {
		return
	}

	proxyBase := fmt.Sprintf("/apps/%s/proxy", appId)

	// Créer le script pour patcher fetch() et XMLHttpRequest
	// Utiliser des backticks pour éviter les problèmes d'échappement
	fetchPatchScript := fmt.Sprintf(`(function() {
  const appId = '%s';
  const proxyBase = '%s';
  
  // Fonction pour déterminer si une URL doit être proxifiée
  function shouldProxy(url) {
    if (!url || typeof url !== 'string') return false;
    if (url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('about:') || url.startsWith('javascript:')) return false;
    return true;
  }
  
  // Fonction pour construire l'URL proxy
  function getProxyUrl(url) {
    try {
      // Si l'URL commence déjà par le proxy base, la retourner telle quelle
      if (url.startsWith(proxyBase)) {
        return url;
      }
      
      const urlObj = new URL(url, window.location.href);
      
      // Ne pas proxifier les requêtes vers le proxy lui-même (pour éviter les boucles)
      if (urlObj.pathname.startsWith('/apps/') && urlObj.pathname.includes('/proxy')) {
        return url;
      }
      
      // Si on est dans un contexte proxy (window.location contient /apps/{id}/proxy),
      // toutes les URLs relatives doivent être proxifiées
      // Sauf les routes explicites du bastion
      const isInProxyContext = window.location.pathname.includes('/apps/') && window.location.pathname.includes('/proxy');
      
      if (urlObj.origin === window.location.origin) {
        // Si c'est une route du bastion explicite, ne pas proxifier
        const bastionRoutes = ['/api', '/login', '/logout', '/admin'];
        const isBastionRoute = bastionRoutes.some(route => urlObj.pathname.startsWith(route) && !urlObj.pathname.startsWith('/apps/'));
        if (isBastionRoute) {
          return url;
        }
        
        // Si on est dans un contexte proxy, proxifier toutes les autres URLs relatives
        if (isInProxyContext) {
          // URL relative sur le même domaine - doit être proxifiée
          // Construire l'URL complète avec le path et la query string
          let proxyPath = urlObj.pathname;
          if (urlObj.search) {
            proxyPath += urlObj.search;
          }
          if (urlObj.hash) {
            proxyPath += urlObj.hash;
          }
          const fullUrl = proxyBase + proxyPath;
          
          // Logger si l'URL est très longue (peut causer des problèmes)
          if (fullUrl.length > 4000) {
            console.warn('Very long URL detected:', fullUrl.length, 'chars. Path:', urlObj.pathname.substring(0, 100));
          }
          
          return fullUrl;
        }
        return url;
      }
      
      // URL externe absolue - toujours proxifier
      const encodedUrl = encodeURIComponent(urlObj.href);
      const fullUrl = proxyBase + '/external?url=' + encodedUrl;
      
      // Logger si l'URL est très longue
      if (fullUrl.length > 4000) {
        console.warn('Very long external URL detected:', fullUrl.length, 'chars');
      }
      
      return fullUrl;
    } catch (e) {
      // Si l'URL est relative sans protocole, essayer de la proxifier quand même
      if (url && !url.startsWith('http') && !url.startsWith('data:') && !url.startsWith('blob:')) {
        // Vérifier si on est dans un contexte proxy
        const isInProxyContext = window.location.pathname.includes('/apps/') && window.location.pathname.includes('/proxy');
        if (isInProxyContext) {
          return proxyBase + (url.startsWith('/') ? url : '/' + url);
        }
      }
      return url;
    }
  }
  
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    let url;
    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof Request) {
      url = input.url;
    } else {
      return originalFetch.apply(this, arguments);
    }
    
    if (!shouldProxy(url)) {
      return originalFetch.apply(this, arguments);
    }
    
    const proxyUrl = getProxyUrl(url);
    if (proxyUrl === url) {
      return originalFetch.apply(this, arguments);
    }
    
    try {
      const proxyRequest = new Request(proxyUrl, init || {});
      return originalFetch(proxyRequest);
    } catch (e) {
      return originalFetch.apply(this, arguments);
    }
  };
  // Patcher aussi document.createElement pour intercepter les balises <link> et <script>
  const originalCreateElement = document.createElement;
  document.createElement = function(tagName, options) {
    const element = originalCreateElement.call(this, tagName, options);
    
    if (tagName.toLowerCase() === 'link' || tagName.toLowerCase() === 'script') {
      const originalSetAttribute = element.setAttribute;
      element.setAttribute = function(name, value) {
        if ((name === 'href' || name === 'src') && shouldProxy(value)) {
          const proxyUrl = getProxyUrl(value);
          if (proxyUrl !== value) {
            return originalSetAttribute.call(this, name, proxyUrl);
          }
        }
        return originalSetAttribute.apply(this, arguments);
      };
      
      // Intercepter aussi les propriétés directes
      if (tagName.toLowerCase() === 'link') {
        Object.defineProperty(element, 'href', {
          set: function(value) {
            if (shouldProxy(value)) {
              const proxyUrl = getProxyUrl(value);
              originalSetAttribute.call(this, 'href', proxyUrl);
            } else {
              originalSetAttribute.call(this, 'href', value);
            }
          },
          get: function() {
            return this.getAttribute('href');
          }
        });
      }
      
      if (tagName.toLowerCase() === 'script') {
        Object.defineProperty(element, 'src', {
          set: function(value) {
            if (shouldProxy(value)) {
              const proxyUrl = getProxyUrl(value);
              originalSetAttribute.call(this, 'src', proxyUrl);
            } else {
              originalSetAttribute.call(this, 'src', value);
            }
          },
          get: function() {
            return this.getAttribute('src');
          }
        });
      }
    }
    
    return element;
  };
  
  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    // Stocker la méthode originale pour référence
    if (typeof method === 'string') {
      this._xhrMethod = method;
    }
    
    if (typeof url === 'string' && shouldProxy(url)) {
      const proxyUrl = getProxyUrl(url);
      if (proxyUrl !== url) {
        // L'URL a été proxifiée, utiliser la nouvelle URL
        // Logger TOUTES les URLs pour debug
        console.log('[BASTION DEBUG] XHR:', method, 'URL length:', proxyUrl.length, 'chars');
        if (proxyUrl.length > 4000) {
          console.warn('[BASTION DEBUG] Very long URL detected! Length:', proxyUrl.length, 'chars');
          console.warn('[BASTION DEBUG] URL preview:', proxyUrl.substring(0, 200));
          console.warn('[BASTION DEBUG] Browser may reject this URL. Consider using POST instead of GET.');
        }
        url = proxyUrl;
      }
    }
    return originalXHROpen.call(this, method, url, async, user, password);
  };
  console.log('Fetch and XMLHttpRequest patched for app:', appId);
})();`, appId, proxyBase)

	// Créer le nœud script
	scriptNode := &html.Node{
		Type: html.ElementNode,
		Data: "script",
		Attr: []html.Attribute{
			{Key: "type", Val: "text/javascript"},
		},
	}

	textNode := &html.Node{
		Type: html.TextNode,
		Data: fetchPatchScript,
	}
	scriptNode.AppendChild(textNode)
	head.InsertBefore(scriptNode, head.FirstChild)
}

// getServiceWorkerCode retourne le code du Service Worker (sans échappements, car json.Marshal s'en occupe)
func (ctrl *ProxyController) getServiceWorkerCode() string {
	return "// Service Worker pour intercepter toutes les requêtes et les faire passer par le proxy\n" +
		"const appId = '{APP_ID}';\n" +
		"\n" +
		"self.addEventListener('install', (event) => {\n" +
		"  self.skipWaiting();\n" +
		"});\n" +
		"\n" +
		"self.addEventListener('activate', (event) => {\n" +
		"  event.waitUntil(clients.claim());\n" +
		"});\n" +
		"\n" +
		"self.addEventListener('fetch', (event) => {\n" +
		"  const url = new URL(event.request.url);\n" +
		"  \n" +
		"  // Ne pas intercepter les requêtes vers le proxy lui-même\n" +
		"  if (url.pathname.startsWith('/apps/') && url.pathname.includes('/proxy')) {\n" +
		"    return;\n" +
		"  }\n" +
		"  \n" +
		"  // Ne pas intercepter les requêtes vers le domaine du bastion (API, etc.)\n" +
		"  if (url.origin === location.origin && !url.pathname.startsWith('/apps/')) {\n" +
		"    return;\n" +
		"  }\n" +
		"  \n" +
		"  // Pour toutes les autres requêtes, les faire passer par le proxy\n" +
		"  const proxyBase = '/apps/' + appId + '/proxy';\n" +
		"  let proxyUrl;\n" +
		"  \n" +
		"  // Si c'est une URL absolue externe, utiliser /external?url=\n" +
		"  if (url.origin !== location.origin) {\n" +
		"    const encodedUrl = encodeURIComponent(url.href);\n" +
		"    proxyUrl = proxyBase + '/external?url=' + encodedUrl;\n" +
		"  } else {\n" +
		"    // URL relative, utiliser directement le proxy\n" +
		"    proxyUrl = proxyBase + url.pathname + url.search + url.hash;\n" +
		"  }\n" +
		"  \n" +
		"  // Créer une nouvelle requête avec les mêmes propriétés mais l'URL proxy\n" +
		"  const proxyRequest = new Request(proxyUrl, {\n" +
		"    method: event.request.method,\n" +
		"    headers: event.request.headers,\n" +
		"    body: event.request.body,\n" +
		"    mode: 'cors',\n" +
		"    credentials: 'include',\n" +
		"    cache: event.request.cache,\n" +
		"    redirect: event.request.redirect\n" +
		"  });\n" +
		"  \n" +
		"  event.respondWith(\n" +
		"    fetch(proxyRequest).catch(err => {\n" +
		"      console.error('Service Worker proxy error:', err);\n" +
		"      return fetch(event.request);\n" +
		"    })\n" +
		"  );\n" +
		"});"
}

// rewriteCookieDomain réécrit le domaine des cookies pour qu'ils fonctionnent avec le proxy
func (ctrl *ProxyController) rewriteCookieDomain(cookieValue string, originalHost, proxyHost string) string {
	// Les cookies peuvent avoir des attributs Domain, Path, etc.
	// On doit réécrire le Domain pour qu'il pointe vers le proxy
	parts := strings.Split(cookieValue, ";")

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "domain=") {
			// Remplacer le domaine par le domaine du proxy
			parts[i] = "Domain=" + proxyHost
		}
		// Supprimer Secure si présent car on pourrait être en HTTP
		if strings.ToLower(part) == "secure" {
			parts[i] = "" // On garde la structure mais on retire Secure
		}
	}

	// Nettoyer les parties vides
	var cleanedParts []string
	for _, part := range parts {
		if part != "" {
			cleanedParts = append(cleanedParts, part)
		}
	}

	return strings.Join(cleanedParts, "; ")
}
