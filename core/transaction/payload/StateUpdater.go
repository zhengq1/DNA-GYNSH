package payload

import (
	"DNA/common/serialization"
	"DNA/crypto"
	. "DNA/errors"
	"bytes"
	"io"
)

const StateUpdaterPayloadVersion byte = 0x00

type StateUpdaterAction byte

const (
	StateUpdaterAction_ADD StateUpdaterAction = 0
	StateUpdaterAction_SUB StateUpdaterAction = 1
)

type StateUpdater struct {
	Namespace []byte
	PubKey    *crypto.PubKey
	Action    StateUpdaterAction
	Cert      []byte
}

func (self *StateUpdater) Data(version byte) []byte {
	var buf bytes.Buffer
	serialization.WriteVarBytes(&buf, self.Namespace)
	self.PubKey.Serialize(&buf)
	buf.WriteByte(byte(self.Action))
	serialization.WriteVarBytes(&buf, self.Cert)

	return buf.Bytes()
}

func (self *StateUpdater) Serialize(w io.Writer, version byte) error {
	_, err := w.Write(self.Data(version))

	return err
}

func (self *StateUpdater) Deserialize(r io.Reader, version byte) error {
	var err error
	self.Namespace, err = serialization.ReadVarBytes(r)
	if err != nil {
		return NewDetailErr(err, ErrNoCode, "[StateUpdater], Namespace Deserialize failed.")
	}
	self.PubKey = new(crypto.PubKey)
	err = self.PubKey.DeSerialize(r)
	if err != nil {
		return NewDetailErr(err, ErrNoCode, "[StateUpdater], PubKey Deserialize failed.")
	}
	var p [1]byte
	n, err := r.Read(p[:])
	if n == 0 {
		return NewDetailErr(err, ErrNoCode, "[StateUpdater], Action Deserialize failed.")
	}
	self.Action = StateUpdaterAction(p[0])
	self.Cert, err = serialization.ReadVarBytes(r)
	if err != nil {
		return NewDetailErr(err, ErrNoCode, "[StateUpdater], Cert Deserialize failed.")
	}

	return nil
}
