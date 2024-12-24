package ech

import (
	"bytes"
	"testing"
)

func TestConfig(t *testing.T) {
	key, conf, err := NewConfig(123, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	spec, err := conf.Spec()
	if err != nil {
		t.Fatalf("Spec() = %v", err)
	}
	if got, want := spec.ID, uint8(123); got != want {
		t.Fatalf("ID = %d, want %d", got, want)
	}
	if got, want := spec.PublicKey, key.PublicKey().Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("PublicKey = %v, want %v", got, want)
	}
	got, err := spec.Bytes()
	if err != nil {
		t.Fatalf("Bytes() = %v", err)
	}
	if want := conf; !bytes.Equal(got, want) {
		t.Fatalf("Bytes = %v, want %v", got, want)
	}
}
