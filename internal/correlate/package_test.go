package correlate

import "testing"

func TestPackageFromPath(t *testing.T) {
	tests := map[string]string{
		"/app/node_modules/esbuild":                                                 "esbuild",
		"/app/node_modules/@esbuild/darwin-arm64/bin":                               "@esbuild/darwin-arm64",
		"/app/node_modules/a/node_modules/b":                                        "b",
		"/private/tmp/pip-install-x8k2ab/requests_0a1b2c3d4e5f60718293a4b5c6d7e8f9": "requests",
		"/tmp/pip-install-x8k2ab/odd_name":                                          "",
		"/opt/homebrew/Cellar/wget/1.25.0/bin":                                      "wget",
		"/usr/local/Cellar/gh":                                                      "gh",
		"/home/dev/project":                                                         "",
	}
	for cwd, want := range tests {
		if got := packageFromPath(cwd); got != want {
			t.Errorf("packageFromPath(%q) = %q, want %q", cwd, got, want)
		}
	}
}
