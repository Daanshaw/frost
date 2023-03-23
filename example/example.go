package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/example"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func XOR(id party.ID, ids party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(example.StartXOR(id, ids), nil)
	if err != nil {
		return err
	}

	test.HandlerLoop(id, h, n)
	_, err = h.Result()
	if err != nil {
		return err
	}

	return nil
}

func FrostKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.Config, error) {
	h, err := protocol.NewMultiHandler(frost.Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.Config), nil
}

func FrostSign(c *frost.Config, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(frost.Sign(c, signers, m), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(frost.Signature)
	if !signature.Verify(c.PublicKey, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func FrostKeygenTaproot(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.TaprootConfig, error) {
	h, err := protocol.NewMultiHandler(frost.KeygenTaproot(id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.TaprootConfig), nil
}
func FrostSignTaproot(c *frost.TaprootConfig, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}
func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// XOR
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}

	// FROST KEYGEN
	frostResult, err := FrostKeygen(id, ids, threshold, n)
	if err != nil {
		return err
	}

	// FROST KEYGEN TAPROOT
	frostResultTaproot, err := FrostKeygenTaproot(id, ids, threshold, n)
	if err != nil {
		return err
	}

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// FROST SIGN
	err = FrostSign(frostResult, id, message, signers, n)
	if err != nil {
		return err
	}

	// FROST SIGN TAPROOT
	err = FrostSignTaproot(frostResultTaproot, id, message, signers, n)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the number of parties: ")
	partiesInput, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	partiesInput = strings.TrimSpace(partiesInput)
	parties, err := strconv.Atoi(partiesInput)
	if err != nil {
		panic(err)
	}

	fmt.Print("Enter the threshold: ")
	thresholdInput, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	thresholdInput = strings.TrimSpace(thresholdInput)
	threshold, err := strconv.Atoi(thresholdInput)
	if err != nil {
		panic(err)
	}

	ids := make(party.IDSlice, parties)
	for i := 0; i < parties; i++ {
		ids[i] = party.ID(fmt.Sprintf("p%d", i))
	}

	messageToSign := []byte("hello")

	net := test.NewNetwork(ids)

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := All(id, ids, threshold, messageToSign, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
