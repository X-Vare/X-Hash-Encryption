package xhe_test

import (
	"fmt"

	"github.com/x-vare/xhe/xhee"
	"github.com/x-vare/xhe/xhpe"
)

// Registration and login, with the client and server halves side by side.
// In a real deployment the two halves run in different processes.
func Example() {
	emails, _ := xhee.NewHasher("email-secret")
	passwords, _ := xhpe.NewHasher("password-pepper", nil, xhpe.WithCost(4))

	// Client, at registration: hash locally, send only the results.
	salt, _ := xhpe.NewSalt()
	emailHash := xhee.ClientHash("Alice@Example.com")
	passwordHash, _ := xhpe.ClientHash("hunter2", salt)

	// Server: add the keyed step and store email_hash, password_hash, salt.
	storedEmail, _ := emails.Hash(emailHash)
	storedPassword, _ := passwords.Hash(passwordHash)

	// Client, at login: the server hands back the salt for this account.
	loginEmail := xhee.ClientHash(" alice@example.com")
	loginPassword, _ := xhpe.ClientHash("hunter2", salt)

	// Server: find the row by email, then check the password.
	ok, _ := emails.Match(loginEmail, storedEmail)
	res, _ := passwords.Verify(loginPassword, storedPassword)
	fmt.Println(ok, res.OK, res.NeedsRehash)

	wrong, _ := xhpe.ClientHash("hunter3", salt)
	res, _ = passwords.Verify(wrong, storedPassword)
	fmt.Println(res.OK)

	// Output:
	// true true false
	// false
}
