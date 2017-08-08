package ChainStore

import (
	"DNA/common/serialization"
	"DNA/crypto"
	"fmt"
	"io"
	"sync"
)

type StateUpdater struct {
	PubKey     *crypto.PubKey
	namespaces map[string]string
	lock       sync.RWMutex
}

func NewStateUpdater(pubkey *crypto.PubKey, namespaces []string) *StateUpdater {
	ns := make(map[string]string, len(namespaces))
	for _, namespace := range namespaces {
		if namespace == "" {
			continue
		}
		ns[namespace] = namespace
	}
	return &StateUpdater{
		PubKey:     pubkey,
		namespaces: ns,
	}
}

func (p *StateUpdater) HasNamespace(namespace string) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	_, ok := p.namespaces[namespace]
	return ok
}

func (p *StateUpdater) AddNamespace(namespace string) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	if _, ok := p.namespaces[namespace]; ok {
		return false
	}
	p.namespaces[namespace] = namespace
	return true
}

func (p *StateUpdater) DelNamespace(namespace string) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	if _, ok := p.namespaces[namespace]; !ok {
		return false
	}
	delete(p.namespaces, namespace)
	return true
}

func (p *StateUpdater) Serialize(w io.Writer) error {
	p.lock.RLock()
	defer p.lock.RUnlock()

	err := p.PubKey.Serialize(w)
	if err != nil {
		return fmt.Errorf("Serialize PubKey error:%s", err)
	}
	count := len(p.namespaces)
	err = serialization.WriteUint32(w, uint32(count))
	if err != nil {
		return fmt.Errorf("serialization.WriteUint32 namespace size:%d error:%s", count, err)
	}
	for namespace := range p.namespaces {
		err = serialization.WriteVarString(w, namespace)
		if err != nil {
			return fmt.Errorf("serialization.WriteVarString namespace:%s error:%s", namespace, err)
		}
	}
	return nil
}

func (p *StateUpdater) Deserialize(r io.Reader) error {
	pubkey := new(crypto.PubKey)
	err := pubkey.DeSerialize(r)
	if err != nil {
		return fmt.Errorf("crypto.PubKey DeSerialize error:%s", err)
	}
	size, err := serialization.ReadUint32(r)
	if err != nil {
		return fmt.Errorf("serialization.ReadUint32 namespace size error:%s", err)
	}
	namespaces := make(map[string]string, size)
	for i := uint32(0); i < size; i++ {
		namespace, err := serialization.ReadVarString(r)
		if err != nil {
			return fmt.Errorf("serialization.ReadVarString namespace error:%s", err)
		}
		namespaces[namespace] = namespace
	}
	p.PubKey = pubkey
	p.namespaces = namespaces
	return nil
}

type StateUpdaterMgr struct {
	states map[string]*StateUpdater
	lock   sync.RWMutex
}

func NewStateUpdaterMgr(stateUpdaters map[crypto.PubKey][]string) *StateUpdaterMgr {
	mgr := &StateUpdaterMgr{
		states: make(map[string]*StateUpdater, len(stateUpdaters)),
	}
	for pubkey, namespaces := range stateUpdaters {
		mgr.AddStateUpdater(NewStateUpdater(&pubkey, namespaces))
	}
	return mgr
}

func (p *StateUpdaterMgr) AddStateUpdater(state *StateUpdater) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.states[p.GetPubKeyId(state.PubKey)] = state
}

func (p *StateUpdaterMgr) GetStateUpdater(pubkey *crypto.PubKey) *StateUpdater {
	p.lock.RLock()
	defer p.lock.RUnlock()

	state, ok := p.states[p.GetPubKeyId(pubkey)]
	if !ok {
		return nil
	}
	return state
}

func (p *StateUpdaterMgr) HasNamespace(pubKey *crypto.PubKey, namespace string) bool {
	state := p.GetStateUpdater(pubKey)
	if state == nil {
		return false
	}
	return state.HasNamespace(namespace)
}

func (p *StateUpdaterMgr) Serialize(w io.Writer) error {
	p.lock.RLock()
	defer p.lock.RUnlock()

	count := len(p.states)
	err := serialization.WriteUint32(w, uint32(count))
	if err != nil {
		return fmt.Errorf("serialization.WriteUint32 state size:%d error:%s", count, err)
	}
	for _, state := range p.states {
		err := state.Serialize(w)
		if err != nil {
			return fmt.Errorf("StateUpdater Serialize error:%s", err)
		}
	}
	return nil
}

func (p *StateUpdaterMgr) Deserialize(r io.Reader) error {
	count, err := serialization.ReadUint32(r)
	if err != nil {
		return fmt.Errorf("serialization.ReadUint32 StateUpdater size error:%s", err)
	}
	p.states = make(map[string]*StateUpdater, count)
	for i := uint32(0); i < count; i++ {
		state := new(StateUpdater)
		err = state.Deserialize(r)
		if err != nil {
			return fmt.Errorf("StateUpdater Deserialize error:%s", err)
		}
		p.AddStateUpdater(state)
	}
	return nil
}

func (p *StateUpdaterMgr) GetPubKeyId(pubKey *crypto.PubKey) string {
	return fmt.Sprintf("%x%x", pubKey.X, pubKey.Y)
}
