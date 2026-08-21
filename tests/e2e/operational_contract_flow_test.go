// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
)

// operationalCloseRecorder observes the order in which host adapters are
// released, so the external consumer lifecycle is asserted on recorded names.
type operationalCloseRecorder struct {
	mu    sync.Mutex
	order []string
}

func (l *operationalCloseRecorder) record(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.order = append(l.order, name)
}

func (l *operationalCloseRecorder) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.order))
	copy(out, l.order)
	return out
}

// operationalRecordingStore wraps an injected store adapter and records its
// release, so a host-owned adapter's lifecycle is observable from outside
// the composition root.
type operationalRecordingStore struct {
	storage.PersistedGrantStore
	name string
	log  *operationalCloseRecorder
}

func (a *operationalRecordingStore) Close() error {
	a.log.record(a.name)
	return nil
}

// TestOperationalContractLifecycleExternalE2E pins the external consumer
// lifecycle flow: a host constructs the root, injects a closable store
// adapter, materializes it through the container, closes the root, and the
// adapter is released. Close is idempotent, and resolving after Close
// panics with godi.ErrProviderClosed.
func TestOperationalContractLifecycleExternalE2E(t *testing.T) {
	t.Parallel()

	recorder := &operationalCloseRecorder{}
	adapter := &operationalRecordingStore{
		PersistedGrantStore: storage_memory.NewMemoryPersistedGrantStore(),
		name:                "persisted grant store",
		log:                 recorder,
	}

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	root.ServerConfig().SetPersistedGrantStore(adapter)
	_, _ = godi.GetRequired[storage.PersistedGrantStore](root).Get(context.Background(), "missing")

	if err := root.Close(); err != nil {
		t.Fatalf("close root: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := recorder.names(); len(got) != 1 || got[0] != "persisted grant store" {
		t.Fatalf("adapter released %d times (%v), want exactly once", len(got), got)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("resolve after close did not panic")
		}
		if err, ok := r.(error); !ok || !errors.Is(err, godi.ErrProviderClosed) {
			t.Fatalf("panic = %v, want godi.ErrProviderClosed", r)
		}
	}()
	_ = godi.GetRequired[storage.PersistedGrantStore](root)
}

const scratchOperationalContractDir = "tests/e2e/scratch-operational-contract"

// TestOperationalContractNoBackgroundActivityRejectsViolationsE2E runs the
// grant store suite the way a host vets an unknown adapter: against a store
// whose method spawns background goroutines. The suite must fail the run and
// name the violated case, so the no-background-activity contract is an
// enforceable gate. The run happens in a scratch package and its failure is
// the assertion; the scratch directory cleans itself up.
func TestOperationalContractNoBackgroundActivityRejectsViolationsE2E(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("mise"); err != nil {
		t.Fatalf("locate mise toolchain: %v", err)
	}

	root := projectRoot(t)
	scratch := filepath.Join(root, scratchOperationalContractDir)
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("clear scratch suite package: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Logf("remove scratch suite package: %v", err)
		}
	})

	writeScratchFile(t, filepath.Join(scratch, "adapters.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchoperationalcontract

import (
	"context"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// goroutineSpawningStore wraps a correct store and spawns several
// short-lived goroutines inside a store method, violating the
// no-background-activity contract. Several goroutines are needed to exceed
// the documented +2 framework-parallel tolerance.
type goroutineSpawningStore struct {
	storage.PersistedGrantStore
}

func (a *goroutineSpawningStore) Store(_ context.Context, grant *models.PersistedGrant) error {
	for range 3 {
		go func() { time.Sleep(50 * time.Millisecond) }()
	}
	return a.PersistedGrantStore.Store(context.Background(), grant)
}
`)

	writeScratchFile(t, filepath.Join(scratch, "adapters_test.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchoperationalcontract

import (
	"testing"

	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	"github.com/gonewx/wicket/storage/storagetest"
)

func TestGoroutineSpawningStoreRunsGrantSuite(t *testing.T) {
	storagetest.RunPersistedGrantStoreSuite(t, func() storage.PersistedGrantStore {
		return &goroutineSpawningStore{PersistedGrantStore: storage_memory.NewMemoryPersistedGrantStore()}
	})
}
`)

	cmd := exec.Command("mise", "exec", "go@"+readGoToolchainPin(t), "--", "go", "test", "./"+scratchOperationalContractDir+"/", "-count=1")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	combined := string(output) + stderr.String()
	if err == nil {
		t.Fatal("suite accepted a store that spawns background goroutines")
	}
	if !strings.Contains(combined, "MUST/NoBackgroundGoroutines") {
		t.Fatalf("suite failure output does not name the violated case:\n%s", combined)
	}
}

// TestOperationalContractUnmaterializedCloseNoWarningE2E pins the close
// contract for an unmaterialized seam: closing it releases nothing, never
// reads the seam, and never emits the in-memory fallback warning.
func TestOperationalContractUnmaterializedCloseNoWarningE2E(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := di.NewServerConfig()
	cfg.AllowInMemoryFallback()
	closer := di.NewlazyPersistedGrantStore(cfg, logger)
	if err := closer.Close(); err != nil {
		t.Fatalf("close unmaterialized seam: %v", err)
	}
	if logged := buf.String(); logged != "" {
		t.Fatalf("unmaterialized close logged a fallback warning: %q", logged)
	}
}
