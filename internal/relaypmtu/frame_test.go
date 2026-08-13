package relaypmtu

import (
	"errors"
	"testing"
)

func TestAuthenticatedExactSizeRoundTrip(t *testing.T) {
	request, err := BuildRequest("pmtu-token", 1280)
	if err != nil {
		t.Fatal(err)
	}
	response, err := Handle(request, func(token string) bool { return token == "pmtu-token" })
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != 1280 || ParseResponse(response, request) != nil {
		t.Fatal("response did not preserve the authenticated probe size and nonce")
	}
	response[len(response)-1] ^= 1
	if !errors.Is(ParseResponse(response, request), ErrAuth) {
		t.Fatal("forged response authentication was accepted")
	}
}

func TestRejectsInvalidFramesAndCredentials(t *testing.T) {
	if _, err := BuildRequest("", MinimumSize); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty token error = %v", err)
	}
	request, err := BuildRequest("right", MinimumSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Handle(request, func(string) bool { return false }); !errors.Is(err, ErrAuth) {
		t.Fatalf("credential error = %v", err)
	}
	request[7] ^= 1
	if _, err := Handle(request, func(string) bool { return true }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("declared size error = %v", err)
	}
}

func TestSizeBounds(t *testing.T) {
	for _, size := range []int{MinimumSize - 1, MaximumSize + 1} {
		if _, err := BuildRequest("token", size); !errors.Is(err, ErrInvalid) {
			t.Fatalf("size %d error = %v", size, err)
		}
	}
}
