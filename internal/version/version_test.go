package version

import "testing"

func TestImplementationCarriesBuildVersion(t *testing.T) {
	old := Version
	Version = "v1.2.3"
	t.Cleanup(func() { Version = old })
	impl := Implementation()
	if impl.Name != "mcp-auth-proxy" || impl.Version != "v1.2.3" {
		t.Fatalf("implementation: %+v", impl)
	}
}
