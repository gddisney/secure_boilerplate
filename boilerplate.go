package secure_boilerplate

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gddisney/guikit"
	"github.com/gddisney/identity_provider"
	"github.com/gddisney/logger"
	"github.com/gddisney/orchid_sync"
	"github.com/gddisney/secure_bootstrap"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"gopkg.in/yaml.v3"
)

type IdentityProvider interface{}

type Config struct {
	Apps  []identity_provider.Application `yaml:"apps"`
	Users []identity_provider.Identity    `yaml:"users"`
}

type Server struct {
	UI           *guikit.GUIKit
	AuthProvider IdentityProvider
	SearchEngine *orchid_sync.Engine
	DB           *ultimate_db.DB
	Router       *secure_network.Router
	Admin        *identity_provider.AdminController
	Audit        *identity_provider.AuditController
	Logger       *logger.LogDispatcher
	EdgeNode     *secure_network.EdgeNode
}

type RouteModule struct {
	Server *Server
}

func (rm *RouteModule) Public(
	pattern string,
	handler http.HandlerFunc,
) {

	rm.Server.Router.Mux.HandleFunc(
		pattern,
		handler,
	)
}

func (rm *RouteModule) Secure(
	pattern string,
	handler http.HandlerFunc,
) {

	protected := func(c *guikit.Context) {
		handler(c.W, c.R)
	}

	rm.Server.Router.Mux.HandleFunc(
		pattern,

		rm.Server.UI.SecureHeaders(
			func(
				w http.ResponseWriter,
				req *http.Request,
			) {

				c := &guikit.Context{
					W:    w,
					R:    req,
					Data: make(map[string]interface{}),
				}

				secure_bootstrap.RequireAuth(
					rm.Server.Router,
					protected,
				)(c)
			},
		),
	)
}

func Start(
	ui *guikit.GUIKit,
	configPath string,
	provider IdentityProvider,
	routeRegister func(routes *RouteModule),
) {

	// --------------------------------------------------
	// CONFIG
	// --------------------------------------------------

	var cfg Config

	if cfgData, err := os.ReadFile(
		configPath,
	); err == nil {

		_ = yaml.Unmarshal(
			cfgData,
			&cfg,
		)
	}

	// --------------------------------------------------
	// PROVIDER
	// --------------------------------------------------

	concreteProvider :=
		provider.(*webauthnext.Provider)

	// --------------------------------------------------
	// EDGE NODE
	// --------------------------------------------------

	edgeNode, err := secure_network.NewEdgeNode(
		context.Background(),
		"iam_data.db",
		nil,
		concreteProvider,
		nil,
	)

	if err != nil {

		log.Fatalf(
			"Failed to initialize edge node: %v",
			err,
		)
	}

	// --------------------------------------------------
	// LOGGER
	// --------------------------------------------------

	logPage := ultimate_db.PageID(200)

	sysLogger, err := logger.NewLogDispatcher(
		"iam_edge_node",
		edgeNode.DB,
		logPage,
		1000,
	)

	if err != nil {

		log.Fatalf(
			"Failed to initialize logger: %v",
			err,
		)
	}

	edgeNode.Logger = sysLogger

	// --------------------------------------------------
	// SEARCH ENGINE
	// --------------------------------------------------

	searchEngine, err := orchid_sync.NewEngine(
		edgeNode.DB,
		edgeNode,
		sysLogger,
	)

	if err != nil {

		log.Fatalf(
			"Failed to initialize OrchidSync: %v",
			err,
		)
	}

	// --------------------------------------------------
	// ROUTER
	// --------------------------------------------------

	r := edgeNode.Router

	r.GUIKit = ui

	if ui != nil {
		r.Mux.Handle("/index", ui.Mux)
	}

	// --------------------------------------------------
	// LOCAL BUS
	// --------------------------------------------------

	bus := make(
		chan secure_network.SystemEvent,
		128,
	)

	r.LocalBus = bus

	// --------------------------------------------------
	// POLICY ENGINE
	// --------------------------------------------------

	pe := secure_policy.NewPolicyEngine(
		edgeNode.DB,
	)

	// --------------------------------------------------
	// ADMIN CONTROLLER
	// --------------------------------------------------

	admin := &identity_provider.AdminController{
		DB:           edgeNode.DB,
		PolicyEngine: pe,
		LocalBus:     bus,
		Logger:       sysLogger,
	}

	// --------------------------------------------------
	// AUDIT CONTROLLER
	// --------------------------------------------------

	audit := identity_provider.NewAuditController(
		searchEngine,
		ui,
	)

	// IMPORTANT:
	// Connect logger -> audit exporter
	sysLogger.RegisterExporter(audit)

	// --------------------------------------------------
	// SCIM
	// --------------------------------------------------

	scim := identity_provider.NewSCIMDaemon(
		edgeNode.DB,
		bus,
		sysLogger,
	)

	go scim.Start()

	// --------------------------------------------------
	// BOOTSTRAP APPS
	// --------------------------------------------------

	for _, app := range cfg.Apps {

		if err := admin.RegisterApp(
			app,
			"system_bootstrap",
		); err != nil {

			sysLogger.Error(
				"Failed registering app: " +
					err.Error(),
			)
		}
	}

	// --------------------------------------------------
	// BOOTSTRAP USERS
	// --------------------------------------------------

	for _, user := range cfg.Users {

		if err := admin.AssignUserToApp(
			user,
			user.SessionID,
			"system_bootstrap",
		); err != nil {

			sysLogger.Error(
				"Failed assigning user: " +
					err.Error(),
			)
		}
	}

	// --------------------------------------------------
	// LOAD GATEWAY KEY
	// --------------------------------------------------

	keyTxn := edgeNode.DB.BeginTxn()

	gatewayPubKey, _ := edgeNode.DB.Read(
		99,
		keyTxn,
		[]byte("mesh_noise_pub"),
	)

	edgeNode.DB.CommitTxn(keyTxn)

	// --------------------------------------------------
	// MESH NODE
	// --------------------------------------------------

	meshNode, err := secure_network.NewMeshNode(
		edgeNode.DB,
		gatewayPubKey,
		sysLogger,
	)

	if err != nil {

		log.Fatalf(
			"Failed creating mesh node: %v",
			err,
		)
	}

	// --------------------------------------------------
	// AUTH BOOTSTRAP
	// --------------------------------------------------

	secure_bootstrap.BootstrapAuth(
		r,
		concreteProvider,
		meshNode,
		"localhost:443",
		sysLogger,
	)

	// --------------------------------------------------
	// ROUTE REGISTRATION
	// --------------------------------------------------

	identity_provider.RegisterRoutes(
		r,
		admin,
		audit,
		pe,
		concreteProvider.SessionManager,
		sysLogger,
		"localhost:443",
	)

	// --------------------------------------------------
	// SERVER OBJECT
	// --------------------------------------------------

	s := &Server{
		UI:           ui,
		AuthProvider: provider,
		SearchEngine: searchEngine,
		DB:           edgeNode.DB,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
		Logger:       sysLogger,
		EdgeNode:     edgeNode,
	}

	// --------------------------------------------------
	// DEFAULT ROUTES
	// --------------------------------------------------

	if ui != nil {

		ui.Mux.HandleFunc(
			"GET /logout",

			func(
				w http.ResponseWriter,
				req *http.Request,
			) {

				secure_bootstrap.HandleLogout(
					w,
					req,
				)
			},
		)

		ui.Mux.HandleFunc(
			"GET /",

			func(
				w http.ResponseWriter,
				req *http.Request,
			) {

				c := &guikit.Context{
					W:    w,
					R:    req,
					Data: make(map[string]interface{}),
				}

				secure_bootstrap.RequireAuth(
					r,

					func(ctx *guikit.Context) {

						ctx.Data["Title"] =
							"Identity Dashboard"

						ui.Render(
							ctx,
							"views/portal",
						)
					},
				)(c)
			},
		)
	}

	// --------------------------------------------------
	// CUSTOM ROUTES
	// --------------------------------------------------

	routeRegister(
		&RouteModule{
			Server: s,
		},
	)

	// --------------------------------------------------
	// START SERVER
	// --------------------------------------------------

	log.Println(
		"Booting Zero-Trust Identity Hub on :443",
	)

	if err := edgeNode.Start(
		"443",
		r.TLSConfig,
	); err != nil {

		log.Fatalf(
			"Edge Node crashed: %v",
			err,
		)
	}
}
