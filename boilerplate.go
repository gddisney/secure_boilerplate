package secure_boilerplate

import (
	"crypto/rand"
	"crypto/rsa"
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

// IdentityProvider is defined as an empty interface. This allows the Go compiler
// to perform the type assertion to *webauthnext.Provider at runtime without failing.
type IdentityProvider interface{}

// Config defines the structure for YAML bootstrap data
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

// Start enforces the boot sequence, loading config and initializing the identity stack
func Start(configPath string, provider IdentityProvider, routeRegister func(s *Server)) {
	// 1. Load Configuration
	cfgData, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// 2. Core Infrastructure
	ui, err := guikit.New("ui.db", "ui.wal")
	if err != nil {
		log.Fatalf("Failed to boot guikit: %v", err)
	}

	// --- ZERO-TRUST INTEGRATION ---
	// Generate the JWT signing key and SessionManager centrally here
	jwtSigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate JWT signing key: %v", err)
	}
	sessionManager := secure_policy.NewSessionManager(ui.DB, jwtSigningKey)

	// Type-assert the dynamic provider
	concreteProvider, ok := provider.(*webauthnext.Provider)
	if !ok {
		log.Fatalf("FATAL: Provided IdentityProvider is not a *webauthnext.Provider")
	}
	
	// Inject the SessionManager into the provider so it can issue the secure JWTs
	concreteProvider.SessionManager = sessionManager
	// ------------------------------

	// Type-assert the dynamic provider into Orchid Sync
	searchEngine, err := orchid_sync.NewEngine("data.db", 443, concreteProvider)
	if err != nil {
		log.Fatalf("Failed to boot search engine: %v", err)
	}

	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	// 3. Mandatory Router Dependencies
	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	// 4. Initialize Identity & Security Stack
	bus := make(chan secure_network.SystemEvent, 10)
	pe := secure_policy.NewPolicyEngine(db)

	admin := &identity_provider.AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
	}

	audit := identity_provider.NewAuditController(db, searchEngine, ui)
	scim := identity_provider.NewSCIMDaemon(db, bus)

	// Start background daemons
	go scim.Start()

	// 5. Bootstrap Flow
	for _, app := range cfg.Apps {
		if err := admin.RegisterApp(app); err != nil {
			log.Printf("Bootstrap error: failed to register app %s: %v", app.ID, err)
		}
	}
	for _, user := range cfg.Users {
		// Uses standard flow: assigns identity to app
		if err := admin.AssignUserToApp(user, user.SessionID); err != nil {
			log.Printf("Bootstrap error: failed to assign user %s: %v", user.Subject, err)
		}
	}

	// 6. Identity & Hardware Handshake
	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)
	gatewayAddress := "localhost:443"

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil {
		log.Fatalf("Mesh Node instantiation failed: %v", err)
	}

	// 7. Strict Auth Flow Bootstrap
	// FIX: Passed concreteProvider instead of the raw interface provider
	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, gatewayAddress)

	// Register identity routes with the SessionManager to enforce cryptographic checks
	identity_provider.RegisterRoutes(r, admin, audit, pe, sessionManager)

	// 8. User Logic Registration
	s := &Server{
		UI:           ui,
		AuthProvider: provider,
		SearchEngine: searchEngine,
		DB:           db,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
	}
	routeRegister(s)

	// 9. Execution
	log.Println("Booting Zero-Trust Edge Node on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
