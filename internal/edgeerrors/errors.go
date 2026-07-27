package edgeerrors

import "fmt"

type Code string

const (
	CodeConfigInvalid                   Code = "config_invalid"
	CodeCredentialReplayed              Code = "credential_replayed"
	CodeCredentialInvalid               Code = "credential_invalid"
	CodeCredentialMalformed             Code = "credential_malformed"
	CodeCredentialKeyUnavailable        Code = "credential_key_unavailable"
	CodeCredentialSignatureInvalid      Code = "credential_signature_invalid"
	CodeCredentialRevocationUnavailable Code = "credential_revocation_unavailable"
	CodeCredentialExpired               Code = "credential_expired"
	CodeCredentialNotYetValid           Code = "credential_not_yet_valid"
	CodeBindingInvalid                  Code = "credential_binding_invalid"
	CodeGenerationStale                 Code = "connector_generation_stale"
	CodeRevoked                         Code = "credential_revoked"
	CodeRunIDInvalid                    Code = "run_id_invalid"
	CodeRunIDMismatch                   Code = "run_id_mismatch"
	CodeRunIDExpired                    Code = "run_id_expired"
	CodeRunIDRevoked                    Code = "run_id_revoked"
	CodeOperationConflict               Code = "operation_conflict"
	CodeRouteConflict                   Code = "route_conflict"
	CodeRouteInvalid                    Code = "route_invalid"
	CodeRouteRevisionStale              Code = "route_revision_stale"
	CodeServiceUnavailable              Code = "service_unavailable"
	CodeStoreCapacity                   Code = "store_capacity_exceeded"
)

type Error struct {
	Code     Code
	Message  string
	Recovery string
	Cause    error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.Cause }

func New(code Code, message, recovery string) *Error {
	return &Error{Code: code, Message: message, Recovery: recovery}
}

func Wrap(code Code, message, recovery string, cause error) *Error {
	return &Error{Code: code, Message: message, Recovery: recovery, Cause: cause}
}

func CodeOf(err error) (Code, bool) {
	for err != nil {
		if typed, ok := err.(*Error); ok {
			return typed.Code, true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = unwrapper.Unwrap()
	}
	return "", false
}

func (e *Error) Format(s fmt.State, verb rune) { fmt.Fprint(s, e.Error()) }
