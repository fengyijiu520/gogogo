package storage

import (
	"testing"
)

func TestNewStoreBootstrapsAdminWithDevelopmentPassword(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	admin := store.GetUser("admin")
	if admin == nil {
		t.Fatal("expected admin user")
	}
	if !store.CheckPassword("admin", "admin") {
		t.Fatal("expected development admin password to be admin")
	}
}
