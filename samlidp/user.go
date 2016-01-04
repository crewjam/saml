package samlidp

// User represents a stored user. The data here are used to
// populate session once the user has authenticated.
type User struct {
	Name           string
	HashedPassword []byte
	Groups         []string
	Email          string
	CommonName     string
	Surname        string
	GivenName      string
}
