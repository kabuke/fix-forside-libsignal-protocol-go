package tests

import (
	"fmt"
	"github.com/kabuke/libsignal-protocol-go/util/keyhelper"
	"testing"
)

func TestRegistrationID(t *testing.T) {
	regID := keyhelper.GenerateRegistrationID()
	fmt.Println(regID)
}
