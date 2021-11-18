package registration

import (
	"crypto"

	"crypto/pqc"
)

type mockUser struct {
	email      string
	regres     *Resource
	privatekey *pqc.PrivateKey
}

func (u mockUser) GetEmail() string                 { return u.email }
func (u mockUser) GetRegistration() *Resource       { return u.regres }
func (u mockUser) GetPrivateKey() crypto.PrivateKey { return u.privatekey }
