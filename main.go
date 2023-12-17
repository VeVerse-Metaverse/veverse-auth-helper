package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"dev.hackerman.me/artheon/veverse-oauth-providers/eos"
	"dev.hackerman.me/artheon/veverse-oauth-providers/le7el"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/discord"
	"github.com/markbates/goth/providers/google"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

//go:embed index.html
var htmlFile embed.FS

func jsonEscape(input string) (string, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	s := string(b)
	return s[1 : len(s)-1], nil
}

var (
	ctx, cancel            = context.WithTimeout(context.Background(), time.Minute*5)
	provider, scope, appId string
	providerCredentials    = map[string]map[string]string{
		"google": {
			"client_id":     "xxxxxxxxxxxx-telmxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com",
			"client_secret": "xxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxx-x",
		},
		"le7el": {
			"client_id":     "le7el-xr",
			"client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
		"eos": {
			"client_id":     "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
		"discord": {
			"client_id":     "xxxxxxxxxxxxxxxxxxx",
			"client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}
	oAuthStateString string
	session          *goth.Session
	srv              *http.Server
)

type server struct {
}

// For some reason, the server handler is called twice (when using Discord specifically), so we need to check if the request has already been handled to prevent double output
var busy = false

// See https://github.com/discord/discord-api-docs/issues/6073 for the issue report

func (s server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if the request path matches the /:provider/callback path
	if r.URL.Path == "/"+provider+"/callback" {
		if r.Method == "GET" {
			if !busy {
				busy = true

				// Check if the state is valid
				if r.URL.Query().Get("state") != oAuthStateString {
					_, _ = fmt.Fprintf(os.Stdout, "error: invalid state")
					os.Exit(1)
					return
				}

				var (
					apiEndpointOverride = os.Getenv("VE_API2_ENDPOINT")
					apiUrl              string
				)
				if apiEndpointOverride == "" {
					apiUrl = "https://api.example.com/v2/oauth-helper/" + provider
				} else {
					apiUrl = apiEndpointOverride + "/v2/oauth-helper/" + provider
				}

				if session == nil {
					_, _ = fmt.Fprintf(os.Stdout, "error: invalid session")
					os.Exit(1)
				}

				retries := 5
				for i := 1; i <= retries; i++ {
					_, err := net.Dial("tcp", "api.example.com:443")
					if i < retries && err != nil {
						time.Sleep(3 * time.Second)
						continue
					} else {
						if retries >= i && err != nil {
							_, _ = fmt.Fprintf(os.Stdout, "error: failed to connect to the server: "+err.Error())
							os.Exit(1)
						} else {
							// Connection succeeded.
							break
						}
					}
				}

				// Get the provider
				p, err := goth.GetProvider(provider)
				if err != nil {
					fmt.Printf("error: failed to get provider: " + err.Error())
					os.Exit(1)
					return
				}

				// Authorize the user
				_, err = (*session).Authorize(p, r.URL.Query())
				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "error: failed to authorize with the provider: "+err.Error())
					os.Exit(1)
					return
				}

				sess := (*session).Marshal()
				jsonSess, err := jsonEscape(sess)

				var resp *http.Response

				maxRetries := 5
				retryDelay := 5 * time.Second
				for i := 0; i < maxRetries; i++ {
					resp, err = http.Post(apiUrl, "application/json", bytes.NewReader([]byte("{\"scope\":\""+r.URL.Query().Get("scope")+"\",\"session\":\""+jsonSess+"\",\"code\": \""+r.URL.Query().Get("code")+"\"}")))
					if err == nil && resp.StatusCode <= 400 {
						// Successful response received, break out of the loop
						break
					}
					time.Sleep(retryDelay)
				}

				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "error: failed to connect to the server: "+err.Error())
					os.Exit(1)
					return
				}

				// Read the response body
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(resp.Body)
				_ = resp.Body.Close()

				// Write the response body to the stdout pipe
				w.Header().Set("Access-Control-Allow-Origin", "*")
				html, err := fs.ReadFile(htmlFile, "index.html")
				if err == nil {
					_, err = w.Write(html)
					if err != nil {
						http.Redirect(w, r, "https://le7el.com", http.StatusMovedPermanently)
					}
				} else {
					_, err = w.Write([]byte("You have been authenticated. You can now close this window and return to the app."))
					if err != nil {
						http.Redirect(w, r, "https://le7el.com", http.StatusMovedPermanently)
					}
				}
				_, _ = fmt.Fprintf(os.Stdout, buf.String())

				// Shutdown the server
				cancel()
			}

			return
		} else if r.Method == "OPTIONS" || r.Method == "HEAD" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
	}
}

func openBrowser(url string) (err error) {
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

func main() {
	// Parse the command line arguments
	flag.StringVar(&provider, "provider", "", "The provider to use for authentication.")
	flag.StringVar(&scope, "scope", "", "The scopes to use for authentication, comma separated.")
	flag.StringVar(&appId, "app-id", "", "The app id to use for authentication.")
	flag.Parse()

	// Check if the provider is valid
	if _, ok := providerCredentials[provider]; !ok {
		fmt.Printf("error: invalid provider")
		os.Exit(1)
		return
	}

	// Create the server and start listening in a new goroutine
	var s server
	go func() {
		srv = &http.Server{
			Handler: s,
			Addr:    ":30003",
		}
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("error: failed to start server: " + err.Error())
			os.Exit(1)
			return
		}
	}()

	if scope == "" {
		goth.UseProviders(
			google.New(providerCredentials["google"]["client_id"], providerCredentials["google"]["client_secret"], "http://127.0.0.1:30003/google/callback"),
			le7el.New(providerCredentials["le7el"]["client_id"], providerCredentials["le7el"]["client_secret"], "http://127.0.0.1:30003/le7el/callback", "offline", "openid"),
			eos.New(providerCredentials["eos"]["client_id"], providerCredentials["eos"]["client_secret"], "http://127.0.0.1:30003/eos/callback"),
			discord.New(providerCredentials["discord"]["client_id"], providerCredentials["discord"]["client_secret"], "http://127.0.0.1:30003/discord/callback", "identify", "email"),
		)
	} else {
		scopes := strings.Split(scope, ",")
		goth.UseProviders(
			google.New(providerCredentials["google"]["client_id"], providerCredentials["google"]["client_secret"], "http://127.0.0.1:30003/google/callback", scopes...),
			le7el.New(providerCredentials["le7el"]["client_id"], providerCredentials["le7el"]["client_secret"], "http://127.0.0.1:30003/le7el/callback", scopes...),
			eos.New(providerCredentials["eos"]["client_id"], providerCredentials["eos"]["client_secret"], "http://127.0.0.1:30003/eos/callback", scopes...),
			discord.New(providerCredentials["discord"]["client_id"], providerCredentials["discord"]["client_secret"], "http://127.0.0.1:30003/discord/callback", scopes...),
		)
	}

	// Get the provider
	p, err := goth.GetProvider(provider)
	if err != nil {
		fmt.Printf("error: failed to get provider: " + err.Error())
		os.Exit(1)
		return
	}

	// Generate a random base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	_, err = io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		fmt.Printf("error: failed to generate state: " + err.Error())
		os.Exit(1)
		return
	}
	oAuthStateString = base64.URLEncoding.EncodeToString(nonceBytes)

	// Begin the authentication process
	sess, err := p.BeginAuth(oAuthStateString)
	if err != nil {
		fmt.Printf("error: failed to begin auth: " + err.Error())
		os.Exit(1)
		return
	}
	session = &sess

	// Get the auth URL
	authURL, err := sess.GetAuthURL()
	if err != nil {
		fmt.Printf("error: failed to get auth url: " + err.Error())
		os.Exit(1)
		return
	}

	if provider == "discord" {
		// Replace the prompt=none with prompt=consent
		authURL = strings.Replace(authURL, "prompt=none", "prompt=consent", -1)
	}

	// Print the auth URL
	_, _ = fmt.Fprint(os.Stdout, "<")
	_, _ = fmt.Fprint(os.Stdout, authURL)
	_, _ = fmt.Fprint(os.Stdout, ">")

	// Open the auth URL in the default browser
	err = openBrowser(authURL)
	if err != nil {
		fmt.Printf("error: failed to open browser: " + err.Error())
		os.Exit(1)
		return
	}

	// Wait for the user to authenticate
	<-ctx.Done()

	// Close the server
	if srv != nil {
		ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer func() {
			cancel()
		}()
		if err = srv.Shutdown(ctxShutDown); err != nil {
			os.Exit(1)
		}
	}
}
