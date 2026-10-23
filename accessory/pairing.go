package accessory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"

	"github.com/tadglines/go-pkgs/crypto/srp"

	"github.com/shabunin/tiny-hap-go/internal/hapcrypto"
	"github.com/shabunin/tiny-hap-go/internal/session"
	"github.com/shabunin/tiny-hap-go/tlv"
)

// pairing is a controller paired with accessory.
type pairing struct {
	id    string
	ltpk  []byte
	admin bool
}

// encodePairings writes pairings like the list pairings response, without state.
func encodePairings(w *tlv.Writer, pp []pairing) {
	for i, p := range pp {
		if i > 0 {
			w.Separator()
		}
		w.String(tlv.Identifier, p.id)
		w.Bytes(tlv.PublicKey, p.ltpk)
		var perm byte
		if p.admin {
			perm = 1
		}
		w.Byte(tlv.Permissions, perm)
	}
}

func decodePairings(b []byte) ([]pairing, error) {
	items, err := tlv.Parse(b)
	if err != nil {
		return nil, err
	}
	var res []pairing
	var p pairing
	flush := func() {
		if p.id != "" {
			res = append(res, p)
		}
		p = pairing{}
	}
	for _, it := range items {
		switch it.Type {
		case tlv.Identifier:
			p.id = string(it.Value)
		case tlv.PublicKey:
			p.ltpk = append([]byte(nil), it.Value...)
		case tlv.Permissions:
			p.admin = len(it.Value) == 1 && it.Value[0] == 1
		case tlv.Separator:
			flush()
		}
	}
	flush()
	return res, nil
}

func (s *Server) loadPairings() error {
	b, err := s.cfg.Store.Get("pairings")
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.pairings, err = decodePairings(b)
	return err
}

// savePairingsLocked stores pairings, s.mu must be held.
func (s *Server) savePairingsLocked() error {
	var w tlv.Writer
	encodePairings(&w, s.pairings)
	return s.cfg.Store.Set("pairings", w.Data())
}

func (s *Server) findPairingLocked(id string) int {
	for i, p := range s.pairings {
		if p.id == id {
			return i
		}
	}
	return -1
}

func tlvError(state, code byte) *response {
	var w tlv.Writer
	w.Byte(tlv.State, state)
	w.Byte(tlv.Error, code)
	return tlvResponse(w.Data())
}

// pairSetup is state of pair-setup between M1 and M6.
type pairSetup struct {
	c   *conn
	ss  *srp.ServerSession
	key []byte // SRP shared key, after M3
}

func newSRP() (*srp.SRP, error) {
	s, err := srp.NewSRP("rfc5054.3072", sha512.New, func(salt, pin []byte) []byte {
		// x = H(s | H(I | ":" | P))
		h := sha512.New()
		h.Write([]byte("Pair-Setup:"))
		h.Write(pin)
		inner := h.Sum(nil)
		h.Reset()
		h.Write(salt)
		h.Write(inner)
		return h.Sum(nil)
	})
	if err != nil {
		return nil, err
	}
	s.SaltLength = 16
	return s, nil
}

func (c *conn) pairSetup(body []byte) *response {
	items, err := tlv.Parse(body)
	if err != nil {
		return &response{status: 400}
	}
	state, _ := items.Byte(tlv.State)
	switch state {
	case 1:
		return c.pairSetupM1(items)
	case 3:
		return c.pairSetupM3(items)
	case 5:
		return c.pairSetupM5(items)
	}
	return &response{status: 400}
}

func (c *conn) pairSetupM1(items tlv.Items) *response {
	s := c.srv
	s.mu.Lock()
	switch {
	case len(s.pairings) > 0:
		s.mu.Unlock()
		return tlvError(2, tlv.ErrUnavailable)
	case s.failed >= maxFailed:
		s.mu.Unlock()
		return tlvError(2, tlv.ErrMaxTries)
	case s.setup != nil && s.setup.c != c:
		s.mu.Unlock()
		return tlvError(2, tlv.ErrBusy)
	}
	// claimed before slow SRP computation, so other connection gets busy error
	setup := &pairSetup{c: c}
	s.setup = setup
	s.mu.Unlock()

	fail := func() *response {
		s.mu.Lock()
		if s.setup == setup {
			s.setup = nil
		}
		s.mu.Unlock()
		return tlvError(2, tlv.ErrUnknown)
	}
	sr, err := newSRP()
	if err != nil {
		return fail()
	}
	salt, verifier, err := sr.ComputeVerifier([]byte(s.cfg.Pin))
	if err != nil {
		return fail()
	}
	setup.ss = sr.NewServerSession([]byte("Pair-Setup"), salt, verifier)

	var w tlv.Writer
	w.Byte(tlv.State, 2)
	w.Bytes(tlv.Salt, salt)
	w.Bytes(tlv.PublicKey, setup.ss.GetB())
	return tlvResponse(w.Data())
}

// currentSetup returns pair-setup of this connection.
func (c *conn) currentSetup() *pairSetup {
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	if c.srv.setup != nil && c.srv.setup.c == c {
		return c.srv.setup
	}
	return nil
}

// failSetup ends pair-setup after wrong setup code or broken message.
func (c *conn) failSetup(state, code byte, counts bool) *response {
	s := c.srv
	s.mu.Lock()
	if s.setup != nil && s.setup.c == c {
		s.setup = nil
	}
	if counts {
		s.failed++
	}
	s.mu.Unlock()
	return tlvError(state, code)
}

func (c *conn) pairSetupM3(items tlv.Items) *response {
	setup := c.currentSetup()
	if setup == nil || setup.ss == nil || setup.key != nil {
		return tlvError(4, tlv.ErrUnknown)
	}
	a, _ := items.Get(tlv.PublicKey)
	proof, _ := items.Get(tlv.Proof)
	key, err := setup.ss.ComputeKey(a)
	if err != nil || !setup.ss.VerifyClientAuthenticator(proof) {
		return c.failSetup(4, tlv.ErrAuthentication, true)
	}
	setup.key = key

	var w tlv.Writer
	w.Byte(tlv.State, 4)
	w.Bytes(tlv.Proof, setup.ss.ComputeAuthenticator(proof))
	return tlvResponse(w.Data())
}

func (c *conn) pairSetupM5(items tlv.Items) *response {
	s := c.srv
	setup := c.currentSetup()
	if setup == nil || setup.key == nil {
		return tlvError(6, tlv.ErrUnknown)
	}
	encKey := hapcrypto.HKDF(setup.key, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	enc, _ := items.Get(tlv.EncryptedData)
	plain, err := hapcrypto.Open(encKey, []byte("PS-Msg05"), enc, nil)
	if err != nil {
		return c.failSetup(6, tlv.ErrAuthentication, false)
	}
	sub, err := tlv.Parse(plain)
	if err != nil {
		return c.failSetup(6, tlv.ErrUnknown, false)
	}
	id, _ := sub.Get(tlv.Identifier)
	ltpk, _ := sub.Get(tlv.PublicKey)
	sig, _ := sub.Get(tlv.Signature)
	ctrlX := hapcrypto.HKDF(setup.key, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	info := append(append(ctrlX[:], id...), ltpk...)
	if len(id) == 0 || len(ltpk) != ed25519.PublicKeySize || !ed25519.Verify(ltpk, info, sig) {
		return c.failSetup(6, tlv.ErrAuthentication, false)
	}

	s.mu.Lock()
	if s.setup != setup || len(s.pairings) > 0 {
		s.mu.Unlock()
		return tlvError(6, tlv.ErrUnavailable)
	}
	s.pairings = []pairing{{id: string(id), ltpk: append([]byte(nil), ltpk...), admin: true}}
	err = s.savePairingsLocked()
	if err != nil {
		s.pairings = nil
	}
	s.setup = nil
	s.failed = 0
	s.mu.Unlock()
	if err != nil {
		logf("saving pairing: %v", err)
		return tlvError(6, tlv.ErrUnknown)
	}

	accX := hapcrypto.HKDF(setup.key, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
	info = append(append(accX[:], s.id...), s.ltpk...)
	var sw tlv.Writer
	sw.String(tlv.Identifier, s.id)
	sw.Bytes(tlv.PublicKey, s.ltpk)
	sw.Bytes(tlv.Signature, ed25519.Sign(s.ltsk, info))

	var w tlv.Writer
	w.Byte(tlv.State, 6)
	w.Bytes(tlv.EncryptedData, hapcrypto.Seal(nil, encKey, []byte("PS-Msg06"), sw.Data(), nil))
	res := tlvResponse(w.Data())
	res.after = func() bool {
		s.advertise()
		return true
	}
	return res
}

// pairVerify is state of pair-verify between M1 and M3.
type pairVerify struct {
	ctrlPub, accPub [32]byte
	shared          [32]byte
	encKey          [32]byte
}

func (c *conn) pairVerify(body []byte) *response {
	items, err := tlv.Parse(body)
	if err != nil {
		return &response{status: 400}
	}
	state, _ := items.Byte(tlv.State)
	switch state {
	case 1:
		return c.pairVerifyM1(items)
	case 3:
		return c.pairVerifyM3(items)
	}
	return &response{status: 400}
}

func (c *conn) pairVerifyM1(items tlv.Items) *response {
	s := c.srv
	ctrlPub, _ := items.Get(tlv.PublicKey)
	if len(ctrlPub) != 32 {
		return tlvError(2, tlv.ErrUnknown)
	}
	v := &pairVerify{}
	copy(v.ctrlPub[:], ctrlPub)
	accPub, accPriv, err := hapcrypto.X25519KeyPair()
	if err != nil {
		return tlvError(2, tlv.ErrUnknown)
	}
	v.accPub = accPub
	v.shared, err = hapcrypto.X25519(accPriv, v.ctrlPub)
	if err != nil {
		return tlvError(2, tlv.ErrAuthentication)
	}
	v.encKey = hapcrypto.HKDF(v.shared[:], "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")

	info := append(append(v.accPub[:], s.id...), v.ctrlPub[:]...)
	var sw tlv.Writer
	sw.String(tlv.Identifier, s.id)
	sw.Bytes(tlv.Signature, ed25519.Sign(s.ltsk, info))

	c.verify = v
	var w tlv.Writer
	w.Byte(tlv.State, 2)
	w.Bytes(tlv.PublicKey, v.accPub[:])
	w.Bytes(tlv.EncryptedData, hapcrypto.Seal(nil, v.encKey, []byte("PV-Msg02"), sw.Data(), nil))
	return tlvResponse(w.Data())
}

func (c *conn) pairVerifyM3(items tlv.Items) *response {
	s := c.srv
	v := c.verify
	c.verify = nil
	if v == nil {
		return tlvError(4, tlv.ErrUnknown)
	}
	enc, _ := items.Get(tlv.EncryptedData)
	plain, err := hapcrypto.Open(v.encKey, []byte("PV-Msg03"), enc, nil)
	if err != nil {
		return tlvError(4, tlv.ErrAuthentication)
	}
	sub, err := tlv.Parse(plain)
	if err != nil {
		return tlvError(4, tlv.ErrUnknown)
	}
	id, _ := sub.Get(tlv.Identifier)
	sig, _ := sub.Get(tlv.Signature)

	s.mu.Lock()
	i := s.findPairingLocked(string(id))
	var p pairing
	if i >= 0 {
		p = s.pairings[i]
	}
	s.mu.Unlock()
	info := append(append(v.ctrlPub[:], id...), v.accPub[:]...)
	if i < 0 || !ed25519.Verify(p.ltpk, info, sig) {
		return tlvError(4, tlv.ErrAuthentication)
	}

	var w tlv.Writer
	w.Byte(tlv.State, 4)
	res := tlvResponse(w.Data())
	// M4 goes plain, everything after it is encrypted
	res.after = func() bool {
		sess := session.NewAccessory(v.shared)
		c.dec = session.NewReader(sess, c.nc)
		c.wmu.Lock()
		c.sess = sess
		c.wmu.Unlock()
		c.vmu.Lock()
		c.ctrlID, c.admin = p.id, p.admin
		c.vmu.Unlock()
		return true
	}
	return res
}

// pairings adds, removes and lists pairings, admins only.
func (c *conn) pairings(body []byte) *response {
	s := c.srv
	items, err := tlv.Parse(body)
	if err != nil {
		return &response{status: 400}
	}
	if state, _ := items.Byte(tlv.State); state != 1 {
		return &response{status: 400}
	}
	if _, admin := c.controller(); !admin {
		return tlvError(2, tlv.ErrAuthentication)
	}
	method, _ := items.Byte(tlv.Method)
	id, _ := items.Get(tlv.Identifier)
	switch method {
	case 3: // add
		ltpk, _ := items.Get(tlv.PublicKey)
		perm, _ := items.Byte(tlv.Permissions)
		if len(id) == 0 || len(ltpk) != ed25519.PublicKeySize {
			return tlvError(2, tlv.ErrUnknown)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if i := s.findPairingLocked(string(id)); i >= 0 {
			if !bytes.Equal(s.pairings[i].ltpk, ltpk) {
				return tlvError(2, tlv.ErrUnknown)
			}
			s.pairings[i].admin = perm == 1
		} else {
			if len(s.pairings) >= maxPairings {
				return tlvError(2, tlv.ErrMaxPeers)
			}
			s.pairings = append(s.pairings, pairing{id: string(id), ltpk: append([]byte(nil), ltpk...), admin: perm == 1})
		}
		if err := s.savePairingsLocked(); err != nil {
			logf("saving pairing: %v", err)
			return tlvError(2, tlv.ErrUnknown)
		}
		var w tlv.Writer
		w.Byte(tlv.State, 2)
		return tlvResponse(w.Data())

	case 4: // remove
		s.mu.Lock()
		removed := []string{string(id)}
		if i := s.findPairingLocked(string(id)); i >= 0 {
			s.pairings = append(s.pairings[:i], s.pairings[i+1:]...)
		}
		hasAdmin := false
		for _, p := range s.pairings {
			hasAdmin = hasAdmin || p.admin
		}
		// without admin nobody could manage accessory, all pairings go
		if !hasAdmin {
			for _, p := range s.pairings {
				removed = append(removed, p.id)
			}
			s.pairings = nil
		}
		err := s.savePairingsLocked()
		s.mu.Unlock()
		if err != nil {
			logf("saving pairings: %v", err)
			return tlvError(2, tlv.ErrUnknown)
		}
		var w tlv.Writer
		w.Byte(tlv.State, 2)
		res := tlvResponse(w.Data())
		res.after = func() bool {
			// connections of removed controllers are closed after response
			own := false
			for _, rid := range removed {
				for _, other := range s.connsOf(rid) {
					if other == c {
						own = true
					} else {
						other.close()
					}
				}
			}
			s.advertise()
			return !own
		}
		return res

	case 5: // list
		s.mu.Lock()
		pp := append([]pairing(nil), s.pairings...)
		s.mu.Unlock()
		var w tlv.Writer
		w.Byte(tlv.State, 2)
		encodePairings(&w, pp)
		return tlvResponse(w.Data())
	}
	return tlvError(2, tlv.ErrUnknown)
}
