package accessory

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

func (s *Server) find(aid, iid uint64) *Characteristic {
	for _, a := range s.accs {
		if a.ID != aid {
			continue
		}
		for _, sv := range a.Services {
			for _, c := range sv.Characteristics {
				if c.ID == iid {
					return c
				}
			}
		}
	}
	return nil
}

type charID struct{ aid, iid uint64 }

// parseIDs parses "1.10,1.11".
func parseIDs(s string) ([]charID, bool) {
	var ids []charID
	for _, part := range strings.Split(s, ",") {
		a, i, ok := strings.Cut(part, ".")
		aid, err1 := strconv.ParseUint(a, 10, 64)
		iid, err2 := strconv.ParseUint(i, 10, 64)
		if !ok || err1 != nil || err2 != nil {
			return nil, false
		}
		ids = append(ids, charID{aid, iid})
	}
	return ids, len(ids) > 0
}

// getCharacteristics answers GET /characteristics?id=1.10,1.11&meta=1&perms=1&type=1&ev=1
func (c *conn) getCharacteristics(query string) *response {
	var ids []charID
	var f charFields
	f.aid, f.value = true, true
	withEv := false
	for _, param := range strings.Split(query, "&") {
		name, value, _ := strings.Cut(param, "=")
		on := value == "1" || value == "true"
		switch name {
		case "id":
			var ok bool
			if ids, ok = parseIDs(value); !ok {
				return statusResponse(400, statusInvalidValue)
			}
		case "meta":
			f.meta = on
		case "perms":
			f.perms = on
		case "type":
			f.typ = on
		case "ev":
			withEv = on
		}
	}
	if len(ids) == 0 {
		return statusResponse(400, statusInvalidValue)
	}

	type result struct {
		id     charID
		ch     *Characteristic
		status int
	}
	results := make([]result, len(ids))
	failed := false
	for i, id := range ids {
		r := result{id: id, ch: c.srv.find(id.aid, id.iid)}
		switch {
		case r.ch == nil:
			r.status = statusNoResource
		case r.ch.Perms&PermRead == 0:
			r.status = statusWriteOnly
		}
		failed = failed || r.status != statusSuccess
		results[i] = r
	}

	w := c.json()
	w.raw(`{"characteristics":[`)
	for _, r := range results {
		w.comma()
		if r.status != statusSuccess {
			w.raw("{")
			w.key("aid")
			w.uint(r.id.aid)
			w.key("iid")
			w.uint(r.id.iid)
			w.key("status")
			w.b = strconv.AppendInt(w.b, int64(r.status), 10)
			w.raw("}")
			continue
		}
		cf := f
		if withEv {
			ev := c.subscribed(r.ch)
			cf.ev = &ev
		}
		w.characteristic(r.ch, cf)
		if failed {
			// 207 needs status of every characteristic, put before closing brace
			w.b = w.b[:len(w.b)-1]
			w.key("status")
			w.raw("0}")
		}
	}
	w.raw("]}")
	status := 200
	if failed {
		status = 207
	}
	return c.jsonResponse(status, w)
}

type putRequest struct {
	Characteristics []struct {
		Aid   uint64          `json:"aid"`
		Iid   uint64          `json:"iid"`
		Value json.RawMessage `json:"value"`
		Ev    *bool           `json:"ev"`
		R     *bool           `json:"r"`
	} `json:"characteristics"`
}

// putCharacteristics writes values and subscribes to events.
func (c *conn) putCharacteristics(body []byte) *response {
	var req putRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Characteristics) == 0 {
		return statusResponse(400, statusInvalidValue)
	}

	type result struct {
		aid, iid uint64
		status   int
		value    any // write response
	}
	results := make([]result, len(req.Characteristics))
	plain := true // all succeeded without write response: 204
	for i, p := range req.Characteristics {
		r := result{aid: p.Aid, iid: p.Iid}
		r.status = c.put(p.Aid, p.Iid, p.Value, p.Ev)
		if r.status == statusSuccess && p.R != nil && *p.R {
			if ch := c.srv.find(p.Aid, p.Iid); ch.Perms&PermWriteResponse != 0 {
				r.value = ch.Value()
			}
		}
		plain = plain && r.status == statusSuccess && r.value == nil
		results[i] = r
	}
	if plain {
		return &response{status: 204}
	}

	w := c.json()
	w.raw(`{"characteristics":[`)
	for _, r := range results {
		w.comma()
		w.raw("{")
		w.key("aid")
		w.uint(r.aid)
		w.key("iid")
		w.uint(r.iid)
		w.key("status")
		w.b = strconv.AppendInt(w.b, int64(r.status), 10)
		if r.value != nil {
			w.key("value")
			w.value(r.value)
		}
		w.raw("}")
	}
	w.raw("]}")
	return c.jsonResponse(207, w)
}

// put handles one entry of write request, returns HAP status.
func (c *conn) put(aid, iid uint64, raw json.RawMessage, ev *bool) int {
	ch := c.srv.find(aid, iid)
	if ch == nil {
		return statusNoResource
	}
	if ev != nil {
		if ch.Perms&PermEvents == 0 {
			return statusNoNotification
		}
		c.subscribe(ch, *ev)
	}
	if raw == nil {
		return statusSuccess
	}
	if ch.Perms&PermWrite == 0 {
		return statusReadOnly
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return statusInvalidValue
	}
	nv, err := ch.convert(v)
	if err != nil {
		return statusInvalidValue
	}
	if ch.Type == "14" && ch.Format == FormatBool {
		// Identify of information service
		c.srv.identify()
		return statusSuccess
	}
	if ch.OnWrite != nil {
		if err := ch.OnWrite(nv); err != nil {
			logf("write %d.%d: %v", aid, iid, err)
			return statusCommunication
		}
	}
	if ch.store(nv) && !slices.Contains(c.changed, ch) {
		c.changed = append(c.changed, ch)
	}
	return statusSuccess
}

// notify sends value of ch to connections subscribed to it, except the one
// that wrote it.
func (s *Server) notify(ch *Characteristic, except *conn) {
	for _, c := range s.connsOf("") {
		if c != except && c.subscribed(ch) {
			if err := c.event(ch); err != nil {
				logf("event to %s: %v", c.nc.RemoteAddr(), err)
			}
		}
	}
}

// event sends current value of ch. It is read with write lock held, so that the
// last event controller gets has the last value, whoever changed it.
func (c *conn) event(ch *Characteristic) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var w jsonWriter
	w.raw(`{"characteristics":[{`)
	w.key("aid")
	w.uint(ch.aid)
	w.key("iid")
	w.uint(ch.ID)
	w.key("value")
	w.value(ch.Value())
	w.raw("}]}")
	hdr := (&response{status: 200, contentType: contentJSON, body: w.b}).header()
	// response line of event has its own protocol name
	hdr = append([]byte("EVENT/1.0"), hdr[len("HTTP/1.1"):]...)
	return c.writeLocked(eventTimeout, hdr, w.b)
}
