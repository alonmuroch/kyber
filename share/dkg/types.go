package dkg

// Init sent by the initiator of the DKG
type Init struct {
	// Operators involved in the DKG
	Operators []uint64
	// T is the threshold for signing
	T uint64
	// Nonce session nonce
	Nonce uint64
	// WithdrawalCredentials for deposit data
	WithdrawalCredentials []byte
	// Fork ethereum fork for signing
	Fork [4]byte
}

type SignedInit struct {
	// Address signing the message
	Address [20]byte
	// Signature of message
	Signature []byte
	Message   Init
}

// SignedInitExchange sent by each node following a valid init message
type SignedInitExchange struct {
	Node      Node
	Signer    uint64
	Signature []byte
}

type Output struct {
	Nonce                       uint64
	EncryptedShare              []byte
	SharePK                     []byte
	ValidatorPK                 []byte
	DepositDataPartialSignature []byte
}

type SignedOutput struct {
	Message   Output
	Signer    uint64
	Signature []byte
}
