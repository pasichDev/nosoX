package blockchain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/pasichDev/noso-go/internal/crypto"
	"github.com/pasichDev/noso-go/internal/types"
)

// NewTransferOrder builds and signs a TRFR-type Order ready to submit to a
// node. Reproduces the construction logic from NosoDart's
// `OrderHandler.generateNewOrder()` (`handlers/order_handler.dart:71-92`)
// so that signatures we produce verify byte-for-byte against the existing
// Flutter wallet flow.
//
//	sign_input = timestamp + senderHash + receiverHash + amount + fee + trxLine
//	trfrID     = TransferHash(timestamp + senderHash + receiverHash + amount + currentBlock)
//	orderID    = OrderHash("1" + timestamp + trfrID)
//
// The `senderKeys` struct must contain the senders address (Hash field of
// the wallet record), the Base64 public key, and the Base64 private key.
// `senderHash` is the senders address; we accept both to mirror the
// Dart API where AddressObject carries both.
type Sender struct {
	Hash       string // Noso address derived from PublicKey
	PublicKey  string // Base64 of uncompressed EC point
	PrivateKey string // Base64 of 32-byte scalar
}

// NewTransferOrder constructs a TRFR order. `block` is the current chain
// tip — used as a salt in TrfrID, matching the Dart behavior.
func NewTransferOrder(s Sender, receiver string, amount int64, message string, timestamp int64, block int64) (*types.Order, error) {
	addr, err := crypto.AddressFromPublicKey(s.PublicKey, crypto.AddressTypeRegular)
	if err != nil || addr != s.Hash || amount <= 0 || timestamp < 0 || block < 0 || block > 2147483647 {
		return nil, errors.New("blockchain: invalid sender or transfer parameters")
	}
	if !crypto.IsValidAddress(receiver) {
		return nil, fmt.Errorf("blockchain.NewTransferOrder: invalid receiver %q", receiver)
	}
	fee := MinimumTransferFee(amount)
	trxLine := int32(1)

	tsStr := strconv.FormatInt(timestamp, 10)
	amtStr := strconv.FormatInt(amount, 10)
	feeStr := strconv.FormatInt(fee, 10)
	trxLineStr := strconv.Itoa(int(trxLine))
	blockStr := strconv.FormatInt(block, 10)

	signInput := tsStr + s.Hash + receiver + amtStr + feeStr + trxLineStr
	// NosoDart Base64-decodes the message bytes before feeding into the
	// signer; matches Pascal's `GetStringSigned` which expects a Base64-
	// encoded input.
	signBytes, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte(signInput)))
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignString(signBytes, s.PrivateKey)
	if err != nil {
		return nil, err
	}

	trfrID := crypto.TransferHash(tsStr + s.Hash + receiver + amtStr + blockStr)
	orderID := crypto.OrderHash("1" + tsStr + trfrID)

	if message == "" {
		message = "null"
	}
	return &types.Order{
		Block:      int32(block),
		OrderID:    orderID,
		OrderLines: 1,
		OrderType:  types.OrderTypeTransfer,
		TimeStamp:  timestamp,
		Reference:  message,
		TrxLine:    trxLine,
		Sender:     s.PublicKey,
		Address:    s.Hash,
		Receiver:   receiver,
		AmmountFee: fee,
		AmmountTrf: amount,
		Signature:  signature,
		TrfrID:     trfrID,
	}, nil
}

// NewCustomOrder constructs a CUSTOM order for setting an alias on the
// senders address. The fee is determined by the current block height.
//
//	sign_input = "Customize this " + senderHash + " " + alias
//
// (Source: `handlers/order_handler.dart:55-69`.)
func NewCustomOrder(s Sender, alias string, timestamp int64, block int64) (*types.Order, error) {
	if alias == "" {
		return nil, errors.New("blockchain.NewCustomOrder: empty alias")
	}
	fee := CustomizationFeeFor(block)
	signInput := "Customize this " + s.Hash + " " + alias
	signature, err := crypto.SignString([]byte(signInput), s.PrivateKey)
	if err != nil {
		return nil, err
	}
	tsStr := strconv.FormatInt(timestamp, 10)
	trfrID := crypto.TransferHash(tsStr + s.Hash + alias)
	orderID := crypto.OrderHash("1" + tsStr + trfrID)
	return &types.Order{
		Block:      int32(block),
		OrderID:    orderID,
		OrderLines: 1,
		OrderType:  types.OrderTypeCustom,
		TimeStamp:  timestamp,
		Reference:  "null",
		TrxLine:    1,
		Sender:     s.PublicKey,
		Address:    s.Hash,
		Receiver:   alias,
		AmmountFee: fee,
		AmmountTrf: 0,
		Signature:  signature,
		TrfrID:     trfrID,
	}, nil
}

// VerifyOrder validates the cryptographic signature on an order. It does
// NOT check balance, fee correctness, or chain-tip plausibility — those
// belong to the mempool/validation layer. The function returns true only
// if the signature on the canonical sign-input verifies against the
// claimed public key.
func VerifyOrder(o *types.Order) bool {
	if o == nil {
		return false
	}
	addr, err := crypto.AddressFromPublicKey(o.Sender, crypto.AddressTypeRegular)
	if err != nil || addr != o.Address {
		return false
	}
	tsStr := strconv.FormatInt(o.TimeStamp, 10)
	amtStr := strconv.FormatInt(o.AmmountTrf, 10)
	feeStr := strconv.FormatInt(o.AmmountFee, 10)
	trxStr := strconv.Itoa(int(o.TrxLine))
	switch o.OrderType {
	case types.OrderTypeTransfer:
		signInput := tsStr + o.Address + o.Receiver + amtStr + feeStr + trxStr
		return crypto.VerifyString([]byte(signInput), o.Signature, o.Sender)
	case types.OrderTypeCustom:
		signInput := "Customize this " + o.Address + " " + o.Receiver
		return crypto.VerifyString([]byte(signInput), o.Signature, o.Sender)
	default:
		// SNDGVT and PROJCT have admin-key signatures handled elsewhere.
		return false
	}
}
