package datacarrier

// Identity returns the authenticated connector-v1 identity bound to this
// carrier. Identity is a value copy, so callers cannot mutate the server's
// admission policy or alter the generation fence used by existing streams.
func (s *Server) Identity() Identity {
	if s == nil {
		return Identity{}
	}
	return s.config.Identity
}
