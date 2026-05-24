package boilerplate

import (
	"log"
	"os"

	"github.com/gddisney/guikit"
	"github.com/gddisney/identity_provider"
	"github.com/gddisney/orchid_sync"
	"github.com/gddisney/secure_bootstrap"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"gopkg.in/yaml.v3"
)

// IdentityProvider is an empty interface, bypassing cross-package compiler restrictions.
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
}

// Start enforces the strict boot sequence for the Zero-Trust Edge Node
func Start(configPath string, provider IdentityProvider, routeRegister func(s *Server)) {
	// 1. Load YAML Configuration
	var cfg Config
	if cfgData, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
	} else {
		log.Printf("[WARNING] Bootstrap config not found at %s. Skipping YAML load.", configPath)
	}

	// 2. Core Infrastructure
	ui, err := guikit.New("ui.db", "ui.wal")
	if err != nil { log.Fatalf("Failed to boot guikit: %v", err) }

	// Safe Runtime Type-Assertion
	concreteProvider, ok := provider.(*webauthnext.Provider)
	if !ok { log.Fatalf("FATAL: Provided IdentityProvider is not a *webauthnext.Provider") }

	searchEngine, err := orchid_sync.NewEngine("iam_data.db", 443, concreteProvider)
	if err != nil { log.Fatalf("Failed to boot search engine: %v", err) }

	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	// 3. Mandatory Router Dependencies
	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	// 4. Initialize Identity & Security Stack
	bus := make(chan secure_network.SystemEvent, 10)
	r.LocalBus = bus 

	pe := secure_policy.NewPolicyEngine(db)
	admin := &identity_provider.AdminController{DB: db, PolicyEngine: pe, LocalBus: bus}
	audit := identity_provider.NewAuditController(db, searchEngine, ui)
	scim := identity_provider.NewSCIMDaemon(db, bus)

	go scim.Start()

	// 5. Execute Bootstrap Configuration
	for _, app := range cfg.Apps { _ = admin.RegisterApp(app) }
	for _, user := range cfg.Users { _ = admin.AssignUserToApp(user, user.SessionID) }

	// 6. Identity & Hardware Handshake
	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)
	gatewayAddress := "localhost:443"

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil { log.Fatalf("Mesh Node instantiation failed: %v", err) }

	// 7. Strict Auth Flow
	// FIX: Passing concreteProvider which has been properly type-asserted
	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, gatewayAddress)

	// 8. Register Pure Identity Routes
	identity_provider.RegisterRoutes(r, admin, audit, pe)

	// 9. Server Definition & Protected Default Route
	s := &Server{UI: ui, AuthProvider: provider, SearchEngine: searchEngine, DB: db, Router: r, Admin: admin, Audit: audit}

	if r.GUIKit != nil {
		r.GUIKit.Get("/logout", secure_bootstrap.HandleLogout)
		r.GUIKit.Get("/", secure_bootstrap.RequireAuth(r, func(c *guikit.Context) {
			c.Data["Title"] = "Identity Dashboard"
			r.GUIKit.Render(c, "views/portal")
		}))
	}

	// 10. Execute Application-Specific Logic
	routeRegister(s)

	// 11. Final Execution
	log.Println("Booting Zero-Trust Identity Hub on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
