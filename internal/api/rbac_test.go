package api

import "testing"

func TestIsAuthorized(t *testing.T) {
	tests := []struct {
		name   string
		role   string
		method string
		path   string
		want   bool
	}{
		{name: "admin can create", role: "admin", method: "POST", path: "/secrets", want: true},
		{name: "admin can read", role: "admin", method: "GET", path: "/secrets/", want: true},
		{name: "admin can delete", role: "admin", method: "DELETE", path: "/secrets/", want: true},
		{name: "admin can list", role: "admin", method: "GET", path: "/secrets", want: true},
		{name: "reader can read", role: "reader", method: "GET", path: "/secrets/", want: true},
		{name: "reader can list", role: "reader", method: "GET", path: "/secrets", want: true},
		{name: "reader cannot create", role: "reader", method: "POST", path: "/secrets", want: false},
		{name: "reader cannot delete", role: "reader", method: "DELETE", path: "/secrets/", want: false},
		{name: "unknown role denied", role: "ghost", method: "GET", path: "/secrets", want: false},
		{name: "unknown path denied", role: "admin", method: "GET", path: "/unknown", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthorized(tt.role, tt.method, tt.path)
			if got != tt.want {
				t.Errorf("isAuthorized(%q, %q, %q) = %v, want %v",
					tt.role, tt.method, tt.path, got, tt.want)
			}
		})
	}
}
