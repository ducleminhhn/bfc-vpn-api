package dualauth

import "errors"

var (
	// ErrAlreadyInLocalMode indicates the system is already in local auth mode
	ErrAlreadyInLocalMode = errors.New("already in local auth mode")
	
	// ErrAlreadyInKeycloakMode indicates the system is already in Keycloak auth mode
	ErrAlreadyInKeycloakMode = errors.New("already in keycloak auth mode")
	
	// ErrFlappingDetected indicates flapping has been detected
	ErrFlappingDetected = errors.New("flapping detected - manual reset required")
	
	// ErrMaxFailoversExceeded indicates max failovers per hour has been exceeded
	ErrMaxFailoversExceeded = errors.New("max failovers per hour exceeded")
	
	// ErrPasswordOutOfSync indicates local password is out of sync with Keycloak
	ErrPasswordOutOfSync = errors.New("password out of sync - please login via Keycloak first")
	
	// ErrAuthUnavailable indicates both auth providers are unavailable
	ErrAuthUnavailable = errors.New("authentication service temporarily unavailable")
	
	// ErrSyncFailed indicates password sync failed
	ErrSyncFailed = errors.New("password sync failed")
)
