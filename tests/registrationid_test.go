package tests

import (
	"fmt"
	"github.com/kabuke/fix-forside-libsignal-protocol-go/util/keyhelper"
	"testing"
)

func TestRegistrationID(t *testing.T) {
	regID := keyhelper.GenerateRegistrationID()
	fmt.Println(regID)
}
