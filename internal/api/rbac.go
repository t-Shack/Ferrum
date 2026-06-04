package api

import "net/http"

// role constants define the two access levels in Ferrum.
const (
	roleAdmin  = "admin"
	roleReader = "reader"
)

// permission represents a specific action on a resource.
type permission struct {
	method string
	path   string
}

// accessPolicy maps each permission to the minimum role required.
var accessPolicy = map[permission]string{
	{method: http.MethodPost, path: "/secrets"}:    roleAdmin,
	{method: http.MethodGet, path: "/secrets"}:     roleReader,
	{method: http.MethodGet, path: "/secrets/"}:    roleReader,
	{method: http.MethodDelete, path: "/secrets/"}: roleAdmin,
}

// roleRank assigns a numeric rank to each role for comparison.
// Higher rank means more access.
var roleRank = map[string]int{
	roleReader: 1,
	roleAdmin:  2,
}

// isAuthorized returns true if the given role is permitted to perform the action.
func isAuthorized(role, method, path string) bool {
	required, exists := accessPolicy[permission{method: method, path: path}]
	if !exists {
		return false
	}
	return roleRank[role] >= roleRank[required]
}
