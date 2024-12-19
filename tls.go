package ech

import (
	"errors"
	"fmt"
	"io"
	"net"
)

var (
	ErrInvalidFormat     = errors.New("invalid format")
	ErrUnexpectedMessage = errors.New("unexpected message")
	ErrIllegalParameter  = errors.New("illegal parameter")
	ErrDecodeError       = errors.New("decode error")
	ErrNoMatch           = errors.New("ech key mismatch")

	extensionNames = map[uint16]string{
		0:      "server_name",
		1:      "max_fragment_length",
		5:      "status_request",
		10:     "supported_groups",
		13:     "signature_algorithms",
		14:     "use_srtp",
		15:     "heartbeat",
		16:     "application_layer_protocol_negotiation",
		18:     "signed_certificate_timestamp",
		19:     "client_certificate_type",
		20:     "server_certificate_type",
		21:     "padding",
		41:     "pre_shared_key",
		42:     "early_data",
		43:     "supported_versions",
		44:     "cookie",
		45:     "psk_key_exchange_modes",
		47:     "certificate_authorities",
		48:     "oid_filters",
		49:     "post_handshake_auth",
		50:     "signature_algorithms_cert",
		51:     "key_share",
		0xfd00: "ech_outer_extensions",
		0xfe0d: "encrypted_client_hello",
	}

	contentTypes = map[uint8]string{
		0:  "invalid",
		20: "change_cipher_spec",
		21: "alert",
		22: "handshake",
		23: "application_data",
	}

	handshakeMessageTypes = map[uint8]string{
		1:   "ClientHello",
		2:   "ServerHello",
		4:   "NewSessionTicket",
		5:   "EndOfEarlyData",
		8:   "EncryptedExtensions",
		11:  "Certificate",
		13:  "CertificateRequest",
		15:  "CertificateVerify",
		20:  "Finished",
		24:  "KeyUpdate",
		254: "message_hash",
	}

	helloRetryRequest = []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
)

func extensionName(t uint16) string {
	if v, ok := extensionNames[t]; ok {
		return v
	}
	return "unknown"
}

func contentType(t uint8) string {
	if v, ok := contentTypes[t]; ok {
		return v
	}
	return "unknown"
}

func readRecord(conn net.Conn) ([]byte, error) {
	record := make([]byte, 16389)
	n, err := io.ReadFull(conn, record[:5])
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	if err != nil {
		return record[:n], err
	}
	length := uint32(record[3])<<8 | uint32(record[4])
	if length > 16384 {
		return record[:n], fmt.Errorf("%w: record length %d > 16384", ErrDecodeError, length)
	}
	nn, err := io.ReadFull(conn, record[n:n+int(length)])
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return record[:n+nn], err
}

func convertErrorsToAlerts(conn net.Conn, err error) {
	switch {
	case err == nil:
	case errors.Is(err, ErrInvalidFormat):
		sendAlert(conn, 0x2 /* fatal */, 0x2F /* Illegal parameter */)
	case errors.Is(err, ErrUnexpectedMessage):
		sendAlert(conn, 0x2 /* fatal */, 0x0a /* Unexpected message */)
	case errors.Is(err, ErrIllegalParameter):
		sendAlert(conn, 0x2 /* fatal */, 0x2F /* Illegal parameter */)
	case errors.Is(err, ErrDecodeError):
		sendAlert(conn, 0x2 /* fatal */, 0x32 /* Decode error */)
	default:
		sendAlert(conn, 0x2 /* fatal */, 0x28 /* Handshake failure */)
	}
}

func sendAlert(w io.WriteCloser, level, description uint8) {
	// https://en.wikipedia.org/wiki/Transport_Layer_Security
	w.Write([]byte{
		0x15,       // alert
		0x03, 0x03, // version TLS 1.2
		0x00, 0x02, // length
		level, description,
	})
	if level == 0x2 {
		w.Close()
	}
}
