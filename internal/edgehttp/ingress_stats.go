package edgehttp

// IngressStats describes live dedicated connector attachments, not admitted
// sessions that have not connected or origin readiness.
type IngressStats struct {
	Sessions, Routes int
	ActiveStreams    uint32
}

func (r *DataCarrierRouteRegistry) Stats() IngressStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var stats IngressStats
	for _, entry := range r.byKey {
		if entry.server == nil {
			continue
		}
		stats.Sessions++
		stats.Routes += len(entry.state.RouteIDs)
		stats.ActiveStreams += uint32(entry.server.ActiveStreams())
	}
	return stats
}
