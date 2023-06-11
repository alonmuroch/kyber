package dkg

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	bls "github.com/drand/kyber-bls12381"
	bls2 "github.com/drand/kyber/sign/bls"
	"testing"
	"time"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/edwards25519"
	"github.com/drand/kyber/sign/schnorr"
	"github.com/drand/kyber/util/random"
	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

type TestNetwork struct {
	boards []*TestBoard
	noops  []uint32
}

func NewTestNetwork(n int) *TestNetwork {
	t := &TestNetwork{}
	for i := 0; i < n; i++ {
		t.boards = append(t.boards, NewTestBoard(uint32(i), n, t))
	}
	return t
}

func (n *TestNetwork) SetNoop(index uint32) {
	n.noops = append(n.noops, index)
}

func (n *TestNetwork) BoardFor(index uint32) *TestBoard {
	for _, b := range n.boards {
		if b.index == index {
			return b
		}
	}
	panic("no such indexes")
}

func (n *TestNetwork) isNoop(i uint32) bool {
	for _, j := range n.noops {
		if i == j {
			return true
		}
	}
	return false
}

func (n *TestNetwork) BroadcastDeal(a *DealBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newDeals <- (*a)
		}
	}
}

func (n *TestNetwork) BroadcastResponse(a *ResponseBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newResps <- *a
		}
	}
}

func (n *TestNetwork) BroadcastJustification(a *JustificationBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newJusts <- *a
		}
	}
}

type TestBoard struct {
	index    uint32
	newDeals chan DealBundle
	newResps chan ResponseBundle
	newJusts chan JustificationBundle
	network  *TestNetwork
	badDeal  bool
	badSig   bool
}

func NewTestBoard(index uint32, n int, network *TestNetwork) *TestBoard {
	return &TestBoard{
		network:  network,
		index:    index,
		newDeals: make(chan DealBundle, n),
		newResps: make(chan ResponseBundle, n),
		newJusts: make(chan JustificationBundle, n),
	}
}

func (t *TestBoard) PushDeals(d *DealBundle) {
	if t.badDeal {
		d.Deals[0].EncryptedShare = []byte("bad bad bad")
	}
	if t.badSig {
		d.Signature = []byte("bad signature my friend")
	}
	t.network.BroadcastDeal(d)
}

func (t *TestBoard) PushResponses(r *ResponseBundle) {
	t.network.BroadcastResponse(r)
}

func (t *TestBoard) PushJustifications(j *JustificationBundle) {
	t.network.BroadcastJustification(j)
}

func (t *TestBoard) IncomingDeal() <-chan DealBundle {
	return t.newDeals
}

func (t *TestBoard) IncomingResponse() <-chan ResponseBundle {
	return t.newResps
}

func (t *TestBoard) IncomingJustification() <-chan JustificationBundle {
	return t.newJusts
}

func SetupProto(tns []*TestNode, dkgC *Config, period time.Duration, network *TestNetwork) {
	for _, n := range tns {
		clock := clock.NewFakeClock()
		n.clock = clock
		n.phaser = NewTimePhaserFunc(func(Phase) {
			clock.Sleep(period)
		})
		n.board = network.BoardFor(n.Index)
		c2 := *n.dkg.c
		proto, err := NewProtocol(&c2, n.board, n.phaser, false)
		if err != nil {
			panic(err)
		}
		n.proto = proto
	}
}

func moveTime(tns []*TestNode, p time.Duration) {
	for _, node := range tns {
		node.clock.Advance(p)
	}
}

func TestProtoFull(t *testing.T) {

	initMsg := &SignedInit{
		Message: Init{
			Operators:             []uint64{1, 2, 3, 4},
			T:                     3,
			Nonce:                 1,
			WithdrawalCredentials: []byte("0x010000000000000000000000506dcf70bea0c0b96039ede2e0429cc1795ffe67"), // taken from https://beaconcha.in/validator/612290#deposits
		},
		Address:   [20]byte{},
		Signature: []byte{},
	}

	/*
		public data
	*/
	n := len(initMsg.Message.Operators)
	thr := initMsg.Message.T
	suite := bls.NewBLS12381Suite()
	g1Suite := suite.G1().(Suite)
	dbOperatorKeys := map[uint64]*rsa.PrivateKey{ // populated with hardcoded for testing, should be taken from ssv contracts
		1: {},
		2: {},
		3: {},
		4: {},
	}
	period := 1 * time.Second
	network := NewTestNetwork(n + 1)
	tns := make([]*TestNode, 0) // local test node

	/**
	Pre phase
	*/
	exchMsgs := make([]*SignedInitExchange, 0)
	for i, id := range initMsg.Message.Operators {
		// happens for each node locally
		require.NoError(t, ValidateInitMessage(initMsg))
		tns = append(tns, NewTestNode(g1Suite, int(id)))

		m := &SignedInitExchange{
			Node: Node{
				Index:  Index(id),
				Public: tns[i].Public,
			},
			Signer: id,
		}
		byts, err := json.Marshal(m) // replace with ssz
		require.NoError(t, err)
		r := sha256.Sum256(byts)
		sig, err := SignRSA(dbOperatorKeys[id], r)
		require.NoError(t, err)
		m.Signature = sig
		exchMsgs = append(exchMsgs, m)
	}

	// upon all SignedInitExchange received (done by every node)
	list := make([]Node, 0)
	for _, msg := range exchMsgs {
		signerID := msg.Signer
		pk := dbOperatorKeys[signerID].PublicKey
		byts, err := json.Marshal(msg.Node)
		require.NoError(t, err)
		require.NoError(t, VerifyRSA(&pk, msg.Signature, byts))

		list = append(list, msg.Node)
	}

	// done by every node
	dkgConf := Config{
		Suite:     g1Suite,
		NewNodes:  list,
		Threshold: int(thr),
		Auth:      bls2.NewSchemeOnG2(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)

	/*
		main drand look for every node
	*/
	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move two periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any.
	// since there is no faults we expect to receive the result only after two
	// periods.
	for i := 0; i < 2; i++ {
		moveTime(tns, period)
		time.Sleep(100 * time.Millisecond)
	}

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	testResults(t, g1Suite, int(thr), n, results)

	/*
		post drand
	*/
	outputs := make([]*SignedOutput, 0)
	for _, res := range results {
		id := uint64(res.Key.Share.I)

		share, err := ResultToShareSecretKey(res)
		require.NoError(t, err)

		validatorPK, err := ResultsToValidatorPK(res.Key.Commitments(), g1Suite)
		require.NoError(t, err)

		encryptedShare, err := Encrypt(&dbOperatorKeys[id].PublicKey, share.Serialize())
		require.NoError(t, err)

		root, _, err := GenerateETHDepositData(
			validatorPK.Serialize(),
			initMsg.Message.WithdrawalCredentials,
			initMsg.Message.Fork,
		)
		partialDepositSig := share.SignByte(root)

		output := Output{
			Nonce:                       initMsg.Message.Nonce,
			EncryptedShare:              encryptedShare,
			SharePK:                     share.GetPublicKey().Serialize(),
			ValidatorPK:                 validatorPK.Serialize(),
			DepositDataPartialSignature: partialDepositSig.Serialize(),
		}
		byts, err := json.Marshal(output) // replace with ssz
		require.NoError(t, err)
		r := sha256.Sum256(byts)
		sig, err := SignRSA(dbOperatorKeys[id], r)
		signedOutput := &SignedOutput{
			Message:   output,
			Signer:    id,
			Signature: sig,
		}
		outputs = append(outputs, signedOutput)
	}

	/*
		verified by DKG requester
	*/
	var validatorPK []byte
	for i, output := range outputs {
		byts, err := json.Marshal(output.Message) // replace with ssz
		require.NoError(t, err)
		require.NoError(t, VerifyRSA(&dbOperatorKeys[output.Signer].PublicKey, output.Signature, byts))

		if i == 0 {
			validatorPK = output.Message.ValidatorPK
		} else {
			require.EqualValues(t, validatorPK, output.Message.ValidatorPK)
		}
	}
}

func TestProtoResharing(t *testing.T) {
	n := 5
	thr := 4
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go func(n *TestNode) {
			optRes := <-n.proto.WaitEnd()
			n.res = optRes.Result
			resCh <- optRes
		}(node)

	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move two periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any.
	// since there is no faults we expect to receive the result only after two
	// periods.
	for i := 0; i < 2; i++ {
		moveTime(tns, period)
		time.Sleep(100 * time.Millisecond)
	}

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	testResults(t, suite, thr, n, results)

	fmt.Printf("\n\n ----- RESHARING ----\n\n")
	// RESHARING
	// we setup now the second group with one node left from old group and two
	// new node
	newN := n + 1
	newT := thr + 1
	var newTns = make([]*TestNode, newN)
	copy(newTns, tns[:n-1])
	//  new node can have the same index as a previous one, separation is made
	newTns[n-1] = NewTestNode(suite, n-1)
	newTns[n] = NewTestNode(suite, n)
	network = NewTestNetwork(newN)
	newList := NodesFromTest(newTns)
	newConf := &Config{
		Suite:        suite,
		NewNodes:     newList,
		OldNodes:     list,
		Threshold:    newT,
		OldThreshold: thr,
		Auth:         schnorr.NewScheme(suite),
	}

	SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)
	SetupProto(newTns, newConf, period, network)

	resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range newTns {
		go func(n *TestNode) {
			optRes := <-n.proto.WaitEnd()
			n.res = optRes.Result
			resCh <- optRes
		}(node)
	}
	// start the phasers
	for _, node := range newTns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move three periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any. A third period
	// is needed to receive all justifications.
	for i := 0; i < 3; i++ {
		moveTime(newTns, period)
		time.Sleep(100 * time.Millisecond)
	}

	// expect all results
	results = nil
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		fmt.Printf("GOT %d RESULTS\n", len(results))
		if len(results) == newN {
			break
		}
	}
	testResults(t, suite, newT, newN, results)

}

func TestProtoThreshold(t *testing.T) {
	n := 5
	realN := 4
	thr := 4
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	tns = tns[:realN]
	network := NewTestNetwork(realN)
	dkgConf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move three periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any. A third period
	// is needed to receive all justifications.
	for i := 0; i < 3; i++ {
		moveTime(tns, period)
		time.Sleep(100 * time.Millisecond)
	}
	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == realN {
			break
		}
	}
	testResults(t, suite, thr, n, results)

}

func TestProtoFullFast(t *testing.T) {
	n := 5
	thr := n
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := Config{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
	}
	// start the phasers
	for _, node := range tns {
		// every node will start when phase starts
		go node.phaser.Start()
	}

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	testResults(t, suite, thr, n, results)
}

func TestProtoResharingAbsent(t *testing.T) {
	n := 4
	thr := 3
	// we setup now the second group with one node left from old group and two
	// new node
	newN := n + 1
	newT := thr + 1

	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go func(n *TestNode) {
			optRes := <-n.proto.WaitEnd()
			n.res = optRes.Result
			resCh <- optRes
		}(node)

	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move two periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any.
	// since there is no faults we expect to receive the result only after two
	// periods.
	for i := 0; i < 2; i++ {
		moveTime(tns, period)
		time.Sleep(100 * time.Millisecond)
	}

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	testResults(t, suite, thr, n, results)

	fmt.Printf("\n\n ----- RESHARING ----\n\n")
	// RESHARING
	var newTns = make([]*TestNode, newN)
	copy(newTns, tns[:n-1])
	//  new node can have the same index as a previous one, separation is made
	newTns[n-1] = NewTestNode(suite, n-1)
	newTns[n] = NewTestNode(suite, n)
	network = NewTestNetwork(newN)
	newList := NodesFromTest(newTns)
	newConf := &Config{
		Suite:        suite,
		NewNodes:     newList,
		OldNodes:     list,
		Threshold:    newT,
		OldThreshold: thr,
		Auth:         schnorr.NewScheme(suite),
	}

	SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)
	SetupProto(newTns, newConf, period, network)
	///
	/// We set a node as registered but offline
	///
	network.SetNoop(newTns[0].Index)
	resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range newTns {
		go func(n *TestNode) {
			optRes := <-n.proto.WaitEnd()
			n.res = optRes.Result
			resCh <- optRes
		}(node)
	}
	// start the phasers
	for _, node := range newTns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move three periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any. A third period
	// is needed to receive all justifications.
	for i := 0; i < 3; i++ {
		moveTime(newTns, period)
		time.Sleep(100 * time.Millisecond)
	}

	// expect results-1 OK and 1 Err
	results = nil
	var errNode error
	for optRes := range resCh {
		if optRes.Error != nil {
			fmt.Printf("GOT ONE ERROR\n")
			require.Nil(t, errNode, "already an error saved!?")
			errNode = optRes.Error
			continue
		}
		results = append(results, optRes.Result)
		fmt.Printf("GOT %d RESULTS\n", len(results))
		if len(results) == newN-1 {
			break
		}
	}
	testResults(t, suite, newT, newN, results)
}

func TestProtoThresholdFast(t *testing.T) {
	n := 5
	thr := 4
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := Config{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)
	// set a node that will send a bad deal such that all deals are received
	// "fast", then the normal rounds are happening
	network.BoardFor(1).badDeal = true

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		if node.Index != 1 {
			go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
		}
	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	// move three periods:
	// nodes already sent they deals, so they need to receive them after one
	// period, then they send their responses. Second period to receive the
	// responses, and then they send the justifications, if any. A third period
	// is needed to receive all justifications.
	// NOTE the first period is ignored by the protocol but timer still sends
	// it.
	for i := 0; i < 3; i++ {
		moveTime(tns, period)
		time.Sleep(100 * time.Millisecond)
	}
	// expect all results consistent except for the node 1
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n-1 {
			break
		}
	}
	testResults(t, suite, thr, n, results)
	// test that they exclude the bad node
	for _, res := range results {
		for _, node := range res.QUAL {
			require.NotEqual(t, uint32(1), node.Index)
		}
	}
}

func generateDeal(idx Index) *DealBundle {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	deals := make([]Deal, 2)
	deals[0].ShareIndex = 56
	deals[1].ShareIndex = 57
	deals[0].EncryptedShare = []byte("My first secure share")
	deals[1].EncryptedShare = []byte("It keeps getting more secure")
	return &DealBundle{
		DealerIndex: idx,
		Deals:       deals,
		Public:      []kyber.Point{suite.Point().Pick(random.New())},
		SessionID:   []byte("Blob"),
	}
}

func TestSet(t *testing.T) {
	s := newSet()
	deal := generateDeal(1)
	s.Push(deal)
	require.NotNil(t, s.vals[1])
	require.Nil(t, s.bad)
	// push a second time shouldn't change the set
	s.Push(deal)
	require.NotNil(t, s.vals[1])
	require.Nil(t, s.bad)

	deal2 := generateDeal(2)
	s.Push(deal2)
	require.Equal(t, 2, len(s.vals))
	require.Nil(t, s.bad)

	// push a different deal
	deal1b := generateDeal(1)
	s.Push(deal1b)
	require.Equal(t, 1, len(s.vals))
	require.Contains(t, s.bad, Index(1))

	// try again, it should fail directly
	s.Push(deal1b)
	require.Equal(t, 1, len(s.vals))
	require.Contains(t, s.bad, Index(1))

}

func TestProtoSkip(t *testing.T) {
	n := 5
	thr := 4
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := Config{
		FastSync:  false,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, period, network)
	for _, tn := range tns {
		tn.proto.skipVerif = true
	}

	network.BoardFor(1).badSig = true

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 2; i++ {
		moveTime(tns, period)
		time.Sleep(100 * time.Millisecond)
	}
	// expect all results
	var results []*Result
	for optRes := range resCh {
		//require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	// check that all dkgs have all good entries
	// that should be the case since signature verification is not performed
	for _, tn := range tns {
		require.True(t, tn.proto.dkg.statuses.CompleteSuccess(), "%d: %p-> %s", tn.Index, tn.proto.dkg, tn.proto.dkg.statuses.String())
	}
}
