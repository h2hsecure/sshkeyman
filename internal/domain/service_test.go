package domain

import "testing"

func TestHashStr(t *testing.T) {
	h1 := hash("test")

	if h1 == 0 {
		t.Fatalf("hash returned zero value")
	}

	h2 := hash("test2")

	if h1 == h2 {
		t.Fatalf("hash collision detected h1: %d h2: %d", h1, h2)
	}
}
