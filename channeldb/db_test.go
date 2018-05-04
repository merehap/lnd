package channeldb

import (
	"bytes"
	"encoding/binary"
	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var (
	initialChannelSummary = &ChannelCloseSummary{
		ChanPoint:         *testOutpoint,
		RemotePub:         pubKey,
		CloseHeight:       123456,
		ShortChanID:       lnwire.ShortChannelID{},
		ChainHash:         chainhash.Hash{},
		ClosingTXID:       chainhash.Hash{},
		Capacity:          btcutil.Amount(500),
		SettledBalance:    btcutil.Amount(500),
		TimeLockedBalance: btcutil.Amount(10000),
		IsPending:         true,
		CloseType:         CooperativeClose,
	}

	// Identical to initialChannelSummary except no longer pending.
	expectedFinalChannelSummary = &ChannelCloseSummary{
		ChanPoint:         *testOutpoint,
		RemotePub:         pubKey,
		CloseHeight:       123456,
		ShortChanID:       lnwire.ShortChannelID{},
		ChainHash:         chainhash.Hash{},
		ClosingTXID:       chainhash.Hash{},
		Capacity:          btcutil.Amount(500),
		SettledBalance:    btcutil.Amount(500),
		TimeLockedBalance: btcutil.Amount(10000),
		IsPending:         false,
		CloseType:         CooperativeClose,
	}
)

func TestOpenWithCreate(t *testing.T) {
	t.Parallel()
	db, cleanup := openTempDB(t)
	defer cleanup()

	if err := db.Close(); err != nil {
		t.Fatalf("unable to close channeldb: %v", err)
	}

	// The path should have been successfully created.
	if !fileExists(db.Path()) {
		t.Fatalf("channeldb failed to create data directory")
	}
}

// TestMarkChanFullyClosed verifies that no errors occur and that
// the correct channel summary is created.
func TestMarkChanFullyClosed(t *testing.T) {
	db, cleanup := openTempDB(t)
	defer cleanup()

	chanPoint := standardChanPoint()
	key := keyFromChanPoint(t, &chanPoint)
	buffer := bytes.Buffer{}
	serializeChannelCloseSummary(&buffer, initialChannelSummary)
	putBucketValue(db, key, buffer.Bytes())

	err := db.MarkChanFullyClosed(&chanPoint)
	require.NoError(t, err)

	updatedChannelSummary := []byte{}
	// Lookup the resulting channel summary in the DB.
	db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("closed-chan-bucket"))
		updatedChannelSummary = bucket.Get(key)
		return nil
	})

	// Get the final summary in struct form so we can have a nice assert message.
	finalSummary, err := deserializeCloseChannelSummary(
		bytes.NewReader(updatedChannelSummary))
	require.NoError(t, err)

	require.Equal(t, expectedFinalChannelSummary, finalSummary)
}

// TestMarkChanFullyClosed_NoClosedChannel verifies that the correct error
// is returned if the channel to be closed doesn't exist in the db.
func TestMarkChanFullyClosed_NoClosedChannel(t *testing.T) {
	db, cleanup := openTempDB(t)
	defer cleanup()

	// Use an empty channel point such that it can't correspond to a channel
	// in the DB.
	err := db.MarkChanFullyClosed(&wire.OutPoint{})

	require.Error(t, err)
	require.Equal(t,
		"no closed channel for chan_point=0000000000000000000000000000000000000000000000000000000000000000:0 found",
		err.Error())
}

// TestMarkChanFullyClosed_FailedDeserialize verifies that the correct error
// is returned if a bad channel summary exists in the database.
func TestMarkChanFullyClosed_FailedDeserialize(t *testing.T) {
	db, cleanup := openTempDB(t)
	defer cleanup()

	chanPoint := standardChanPoint()
	// Set up the DB with an empty value that can't be a valid summary.
	putBucketValue(db, keyFromChanPoint(t, &chanPoint), []byte{})

	err := db.MarkChanFullyClosed(&chanPoint)

	require.Error(t, err)
	require.Equal(t, "EOF", err.Error())
}

// Add a key/value pair to the DB.
func putBucketValue(db *DB, key []byte, value []byte) {
	db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("closed-chan-bucket"))
		bucket.Put(key, value)
		return nil
	})
}

// Create a valid channel point.
func standardChanPoint() wire.OutPoint {
	hash := [32]byte{}
	copy(hash[:], []byte("key")[:])
	return wire.OutPoint{Hash: hash, Index: 0}
}

// Format a channel point into its DB bucket key format.
func keyFromChanPoint(t *testing.T, chanPoint *wire.OutPoint) []byte {
	var b bytes.Buffer
	if _, err := b.Write(chanPoint.Hash[:]); err != nil {
		require.NoError(t, err)
	}
	if err := binary.Write(&b, byteOrder, chanPoint.Index); err != nil {
		require.NoError(t, err)
	}

	return b.Bytes()
}

func openTempDB(t *testing.T) (*DB, func()) {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName, err := ioutil.TempDir("", "channeldb")
	if err != nil {
		t.Fatalf("unable to create temp dir: %v", err)
	}

	// Next, open thereby creating channeldb for the first time.
	dbPath := filepath.Join(tempDirName, "cdb")
	cdb, err := Open(dbPath)
	if err != nil {
		t.Fatalf("unable to create channeldb: %v", err)
	}

	return cdb, func() {
		defer cdb.Close()
		defer os.RemoveAll(cdb.Path())
	}
}
