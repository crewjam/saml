package samlidp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/zenazn/goji/web"
	"golang.org/x/crypto/bcrypt"
)

// User represents a stored user. The data here are used to
// populate user once the user has authenticated.
type User struct {
	Name              string   `json:"name"`
	PlaintextPassword *string  `json:"password,omitempty"` // not stored
	HashedPassword    []byte   `json:"hashed_password,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Email             string   `json:"email,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	Surname           string   `json:"surname,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
}

func (s *Server) HandleListUsers(c web.C, w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.List("/users/")
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Users []string `json:"users"`
	}{Users: users})
}

func (s *Server) HandleGetUser(c web.C, w http.ResponseWriter, r *http.Request) {
	user := User{}
	err := s.Store.Get(fmt.Sprintf("/users/%s", c.URLParams["id"]), &user)
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	user.HashedPassword = nil
	json.NewEncoder(w).Encode(user)
}

func (s *Server) HandlePutUser(c web.C, w http.ResponseWriter, r *http.Request) {
	user := User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	user.Name = c.URLParams["id"]

	if user.PlaintextPassword != nil {
		var err error
		user.HashedPassword, err = bcrypt.GenerateFromPassword([]byte(*user.PlaintextPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("ERROR: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		existingUser := User{}
		err := s.Store.Get(fmt.Sprintf("/users/%s", c.URLParams["id"]), &existingUser)
		switch {
		case err == nil:
			user.HashedPassword = existingUser.HashedPassword
		case err == ErrNotFound:
			// nop
		default:
			log.Printf("ERROR: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
	user.PlaintextPassword = nil

	err := s.Store.Put(fmt.Sprintf("/users/%s", c.URLParams["id"]), &user)
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandleDeleteUser(c web.C, w http.ResponseWriter, r *http.Request) {
	err := s.Store.Delete(fmt.Sprintf("/users/%s", c.URLParams["id"]))
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
