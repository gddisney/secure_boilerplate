package secure_boilerplate

import (
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
	// LOAD CONFIG
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
	// AUTH PROVIDER
	// --------------------------------------------------

	concreteProvider :=
		provider.(*webauthnext.Provider)

	// --------------------------------------------------
	// SEARCH ENGINE
	// --------------------------------------------------

	searchEngine, err := orchid_sync.NewEngine(
		"iam_data.db",
		443,
		concreteProvider,
	)

	if err != nil {
		log.Fatalf(
			"Failed to initialize OrchidSync: %v",
			err,
		)
	}

	edgeNode := searchEngine.NetNode()

	r := edgeNode.Router

	r.GUIKit = ui

	if ui != nil {
		r.Mux.Handle("/index", ui.Mux)
	}

	// --------------------------------------------------
	// LOCAL EVENT BUS
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
	// LOGGER
	// --------------------------------------------------

	rpcMod, ok := r.Modules["mesh_rpc"]

	if !ok {
		log.Fatal(
			"mesh_rpc module not found",
		)
	}

	rpcManager :=
		rpcMod.(*secure_network.RPCManager)

	sysLogger, err := logger.NewRPCLogger(
		rpcManager,
		"iam_edge_node",
		1000,
		"logs.wal",
	)

	if err != nil {
		log.Fatalf(
			"Failed to initialize logger: %v",
			err,
		)
	}

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

	audit :=
		identity_provider.NewAuditController(
			searchEngine,
			ui,
		)

	// IMPORTANT FIX:
	// CONNECT LOGGER -> AUDIT EXPORTER
	sysLogger.RegisterExporter(audit)

	// --------------------------------------------------
	// SCIM DAEMON
	// --------------------------------------------------

	scim := identity_provider.NewSCIMDaemon(
		edgeNode.DB,
		bus,
		sysLogger,
	)

	go scim.Start()

	// --------------------------------------------------
	// BOOTSTRAP CONFIG APPS
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
	// MESH NODE
	// --------------------------------------------------

	keyTxn := edgeNode.DB.BeginTxn()

	gatewayPubKey, _ := edgeNode.DB.Read(
		99,
		keyTxn,
		[]byte("mesh_noise_pub"),
	)

	edgeNode.DB.CommitTxn(keyTxn)

	meshNode, err := secure_network.NewMeshNode(
		edgeNode.DB,
		gatewayPubKey,
		sysLogger,
	)

	if err != nil {

		log.Fatalf(
			"Failed to create mesh node: %v",
			err,
		)
	}

	// --------------------------------------------------
	// BOOTSTRAP AUTH
	// --------------------------------------------------

	secure_bootstrap.BootstrapAuth(
		r,
		concreteProvider,
		meshNode,
		"localhost:443",
		sysLogger,
	)

	// --------------------------------------------------
	// REGISTER ROUTES
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
	// USER ROUTES
	// --------------------------------------------------

	routeRegister(
		&RouteModule{
			Server: s,
		},
	)

	// --------------------------------------------------
	// START NODE
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
