package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/awalterschulze/gographviz"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/lightningnetwork/lnd/cmd"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcutil"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TODO(roasbeef): expose all fee conf targets

var (
	// ErrBadAddressFormat occurs if a user provides a bad LightningAddress.
	ErrBadAddressFormat = fmt.Errorf(
		"target address expected in format: pubkey@host:port")

	// ErrUnnecessaryArgumentForDebugSend if unnecessary args are specified
	// on a debug send.
	ErrUnnecessaryArgumentForDebugSend = fmt.Errorf("do not provide a payment hash with debug send")

	// ErrMultipleFeeArgs occurs if multiple conflicting ways to specify
	// fees were provided.
	ErrMultipleFeeArgs = fmt.Errorf(
		"either conf_target or sat_per_byte should be set, but not both")

	// ErrBadChanPointFormat occurs if the chan_point was not in the correct format.
	ErrBadChanPointFormat = fmt.Errorf("expecting chan_point to be in format of: txid:index")
)

func printJSONToWriter(writer io.Writer, resp interface{}) {
	b, err := json.Marshal(resp)
	if err != nil {
		fatal(err)
	}

	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	out.WriteString("\n")
	out.WriteTo(writer)
}

func printRespJSONToWriter(writer io.Writer, resp proto.Message) {
	jsonMarshaler := &jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "    ",
	}

	jsonStr, err := jsonMarshaler.MarshalToString(resp)
	if err != nil {
		fmt.Fprintln(writer, "unable to decode response: ", err)
		return
	}

	fmt.Fprintln(writer, jsonStr)
}

// actionDecoratorWithClient is the same as actionDecorator except it allows
// the LightningClient to be configurable and handles client cleanUp()
// TODO(merehap): Replace actionDecorator with this once all commands have been
// migrated over.
func actionDecoratorWithClient(
	f func(*cli.Context, lnrpc.LightningClient, io.Writer) error) func(*cli.Context) error {

	return func(ctx *cli.Context) error {
		client, cleanUp := getClient(ctx)
		defer cleanUp()

		err := f(ctx, client, os.Stdout)
		if err != nil {
			// lnd might be active, but not possible to contact
			// using RPC if the wallet is encrypted. If we get
			// error code Unimplemented, it means that lnd is
			// running, but the RPC server is not active yet (only
			// WalletUnlocker server active) and most likely this
			// is because of an encrypted wallet.
			s, ok := status.FromError(err)
			if ok && s.Code() == codes.Unimplemented {
				return fmt.Errorf("Wallet is encrypted. " +
					"Please unlock using 'lncli unlock', " +
					"or set password using 'lncli create'" +
					" if this is the first time starting " +
					"lnd.")
			}
			return err
		}

		return nil
	}
}

// actionDecorator is used to add additional information and error handling
// to command actions.
func actionDecorator(f func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		if err := f(c); err != nil {
			// lnd might be active, but not possible to contact
			// using RPC if the wallet is encrypted. If we get
			// error code Unimplemented, it means that lnd is
			// running, but the RPC server is not active yet (only
			// WalletUnlocker server active) and most likely this
			// is because of an encrypted wallet.
			s, ok := status.FromError(err)
			if ok && s.Code() == codes.Unimplemented {
				return fmt.Errorf("Wallet is encrypted. " +
					"Please unlock using 'lncli unlock', " +
					"or set password using 'lncli create'" +
					" if this is the first time starting " +
					"lnd.")
			}
			return err
		}
		return nil
	}
}

var newAddressCommand = cli.Command{
	Name:      "newaddress",
	Usage:     "Generates a new address.",
	ArgsUsage: "address-type",
	Description: `
	Generate a wallet new address. Address-types has to be one of:
	    - p2wkh:  Push to witness key hash
	    - np2wkh: Push to nested witness key hash
	    - p2pkh:  Push to public key hash (can't be used to fund channels)`,
	Action: actionDecoratorWithClient(newAddress),
}

func newAddress(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)
	stringAddrType, err := ext.StringPositionalArg("AddressType")
	if err != nil {
		return err
	}

	// Map the string encoded address type, to the concrete typed address
	// type enum. An unrecognized address type will result in an error.
	var addrType lnrpc.NewAddressRequest_AddressType
	switch stringAddrType { // TODO(roasbeef): make them ints on the cli?
	case "p2wkh":
		addrType = lnrpc.NewAddressRequest_WITNESS_PUBKEY_HASH
	case "np2wkh":
		addrType = lnrpc.NewAddressRequest_NESTED_PUBKEY_HASH
	case "p2pkh":
		addrType = lnrpc.NewAddressRequest_PUBKEY_HASH
	default:
		return fmt.Errorf("invalid address type %v, support address type "+
			"are: p2wkh, np2wkh, p2pkh", stringAddrType)
	}

	ctxb := context.Background()
	addr, err := client.NewAddress(ctxb, &lnrpc.NewAddressRequest{
		Type: addrType,
	})
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, addr)
	return nil
}

var sendCoinsCommand = cli.Command{
	Name:      "sendcoins",
	Usage:     "Send bitcoin on-chain to an address",
	ArgsUsage: "addr amt",
	Description: `
	Send amt coins in satoshis to the BASE58 encoded bitcoin address addr.

	Fees used when sending the transaction can be specified via the --conf_target, or 
	--sat_per_byte optional flags.
	
	Positional arguments and flags can be used interchangeably but not at the same time!
	`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Usage: "the BASE58 encoded bitcoin address to send coins to on-chain",
		},
		// TODO(roasbeef): switch to BTC on command line? int may not be sufficient
		cli.Int64Flag{
			Name:  "amt",
			Usage: "the number of bitcoin denominated in satoshis to send",
		},
		cli.Int64Flag{
			Name: "conf_target",
			Usage: "(optional) the number of blocks that the " +
				"transaction *should* confirm in, will be " +
				"used for fee estimation",
		},
		cli.Int64Flag{
			Name: "sat_per_byte",
			Usage: "(optional) a manual fee expressed in " +
				"sat/byte that should be used when crafting " +
				"the transaction",
		},
	},
	Action: actionDecoratorWithClient(sendCoins),
}

func sendCoins(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)

	if !ext.ArgsPresent() {
		cli.ShowCommandHelp(ctx, "sendcoins")
		return nil
	}

	if ext.IsFlagSet("conf_target") && ext.IsFlagSet("sat_per_byte") {
		return ErrMultipleFeeArgs
	}

	addr, err := ext.StringArg("addr")
	if err != nil {
		return err
	}

	amt, err := ext.Int64Arg("amt")
	if err != nil {
		return err
	}

	ctxb := context.Background()

	req := &lnrpc.SendCoinsRequest{
		Addr:       addr,
		Amount:     amt,
		TargetConf: int32(ext.Int64Flag("conf_target")),
		SatPerByte: ext.Int64Flag("sat_per_byte"),
	}
	txid, err := client.SendCoins(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, txid)
	return nil
}

var sendManyCommand = cli.Command{
	Name:      "sendmany",
	Usage:     "Send bitcoin on-chain to multiple addresses.",
	ArgsUsage: "send-json-string [--conf_target=N] [--sat_per_byte=P]",
	Description: `
	Create and broadcast a transaction paying the specified amount(s) to the passed address(es).

	The send-json-string' param decodes addresses and the amount to send 
	respectively in the following format:

	    '{"ExampleAddr": NumCoinsInSatoshis, "SecondAddr": NumCoins}'
	`,
	Flags: []cli.Flag{
		cli.Int64Flag{
			Name: "conf_target",
			Usage: "(optional) the number of blocks that the transaction *should* " +
				"confirm in, will be used for fee estimation",
		},
		cli.Int64Flag{
			Name: "sat_per_byte",
			Usage: "(optional) a manual fee expressed in sat/byte that should be " +
				"used when crafting the transaction",
		},
	},
	Action: actionDecoratorWithClient(sendMany),
}

func sendMany(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	var amountToAddr map[string]int64

	ext := cmd.NewArgExtractor(ctx)

	jsonMap, err := ext.StringPositionalArg("JSON Map")
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(jsonMap), &amountToAddr); err != nil {
		return err
	}

	if ext.IsFlagSet("conf_target") && ext.IsFlagSet("sat_per_byte") {
		return ErrMultipleFeeArgs
	}

	ctxb := context.Background()

	txid, err := client.SendMany(ctxb, &lnrpc.SendManyRequest{
		AddrToAmount: amountToAddr,
		TargetConf:   int32(ext.Int64Flag("conf_target")),
		SatPerByte:   ext.Int64Flag("sat_per_byte"),
	})
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, txid)
	return nil
}

var connectCommand = cli.Command{
	Name:      "connect",
	Usage:     "Connect to a remote lnd peer",
	ArgsUsage: "<pubkey>@host",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "perm",
			Usage: "If set, the daemon will attempt to persistently " +
				"connect to the target peer.\n" +
				"           If not, the call will be synchronous.",
		},
	},
	Action: actionDecoratorWithClient(connectPeer),
}

func connectPeer(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)

	targetAddress, err := ext.StringPositionalArg("Target Address")
	if err != nil {
		return err
	}

	splitAddr := strings.Split(targetAddress, "@")
	if len(splitAddr) != 2 {
		return ErrBadAddressFormat
	}

	addr := &lnrpc.LightningAddress{
		Pubkey: splitAddr[0],
		Host:   splitAddr[1],
	}
	req := &lnrpc.ConnectPeerRequest{
		Addr: addr,
		Perm: ext.BoolFlag("perm"),
	}

	lnid, err := client.ConnectPeer(context.Background(), req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, lnid)
	return nil
}

var disconnectCommand = cli.Command{
	Name:      "disconnect",
	Usage:     "Disconnect a remote lnd peer identified by public key",
	ArgsUsage: "<pubkey>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "node_key",
			Usage: "The hex-encoded compressed public key of the peer " +
				"to disconnect from",
		},
	},
	Action: actionDecoratorWithClient(disconnectPeer),
}

func disconnectPeer(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	pubKey, err := ext.StringArg("node_key")
	if err != nil {
		return err
	}

	req := &lnrpc.DisconnectPeerRequest{
		PubKey: pubKey,
	}

	lnid, err := client.DisconnectPeer(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, lnid)
	return nil
}

// TODO(roasbeef): change default number of confirmations
var openChannelCommand = cli.Command{
	Name:  "openchannel",
	Usage: "Open a channel to a node or an existing peer.",
	Description: `
	Attempt to open a new channel to an existing peer with the key node-key
	optionally blocking until the channel is 'open'.

	One can also connect to a node before opening a new channel to it by
	setting its host:port via the --connect argument. For this to work,
	the node_key must be provided, rather than the peer_id. This is optional.

	The channel will be initialized with local-amt satoshis local and push-amt
	satoshis for the remote node. Once the channel is open, a channelPoint (txid:vout)
	of the funding output is returned.

	One can manually set the fee to be used for the funding transaction via either
	the --conf_target or --sat_per_byte arguments. This is optional.`,
	ArgsUsage: "node-key local-amt push-amt",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "node_key",
			Usage: "the identity public key of the target node/peer " +
				"serialized in compressed format",
		},
		cli.StringFlag{
			Name:  "connect",
			Usage: "(optional) the host:port of the target node",
		},
		cli.IntFlag{
			Name:  "local_amt",
			Usage: "the number of satoshis the wallet should commit to the channel",
		},
		cli.IntFlag{
			Name: "push_amt",
			Usage: "the number of satoshis to push to the remote " +
				"side as part of the initial commitment state",
		},
		cli.BoolFlag{
			Name:  "block",
			Usage: "block and wait until the channel is fully open",
		},
		cli.Int64Flag{
			Name: "conf_target",
			Usage: "(optional) the number of blocks that the " +
				"transaction *should* confirm in, will be " +
				"used for fee estimation",
		},
		cli.Int64Flag{
			Name: "sat_per_byte",
			Usage: "(optional) a manual fee expressed in " +
				"sat/byte that should be used when crafting " +
				"the transaction",
		},
		cli.BoolFlag{
			Name: "private",
			Usage: "make the channel private, such that it won't " +
				"be announced to the greater network, and " +
				"nodes other than the two channel endpoints " +
				"must be explicitly told about it to be able " +
				"to route through it",
		},
		cli.Int64Flag{
			Name: "min_htlc_msat",
			Usage: "(optional) the minimum value we will require " +
				"for incoming HTLCs on the channel",
		},
	},
	Action: actionDecoratorWithClient(openChannel),
}

func openChannel(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	// TODO(roasbeef): add deadline to context
	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)

	// Show command help if no arguments provided
	if !ext.ArgsPresent() {
		cli.ShowCommandHelp(ctx, "openchannel")
		return nil
	}

	req := &lnrpc.OpenChannelRequest{
		TargetConf:  int32(ext.Int64Flag("conf_target")),
		SatPerByte:  ext.Int64Flag("sat_per_byte"),
		MinHtlcMsat: ext.Int64Flag("min_htlc_msat"),
	}

	var err error
	req.NodePubkey, err = ext.HexArg("node_key")
	if err != nil {
		return err
	}

	// As soon as we can confirm that the node's node_key was set, rather
	// than the peer_id, we can check if the host:port was also set to
	// connect to it before opening the channel.
	if req.NodePubkey != nil && ext.IsFlagSet("connect") {
		addr := &lnrpc.LightningAddress{
			Pubkey: hex.EncodeToString(req.NodePubkey),
			Host:   ext.StringFlag("connect"),
		}

		req := &lnrpc.ConnectPeerRequest{
			Addr: addr,
			Perm: false,
		}

		// Check if connecting to the node was successful.
		// We discard the peer id returned as it is not needed.
		_, err := client.ConnectPeer(ctxb, req)
		if err != nil &&
			!strings.Contains(err.Error(), "already connected") {
			return err
		}
	}

	req.LocalFundingAmount, err = ext.Int64Arg("local_amt")
	if err != nil {
		return err
	}

	req.PushSat, err = ext.Int64ArgWithDefault("push_amt", 0)
	if err != nil {
		return err
	}

	req.Private = ext.BoolFlag("private")

	stream, err := client.OpenChannel(ctxb, req)
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		switch update := resp.Update.(type) {
		case *lnrpc.OpenStatusUpdate_ChanPending:
			txid, err := chainhash.NewHash(update.ChanPending.Txid)
			if err != nil {
				return err
			}

			printJSONToWriter(writer, struct {
				FundingTxid string `json:"funding_txid"`
			}{
				FundingTxid: txid.String(),
			},
			)

			if !ext.BoolFlag("block") {
				return nil
			}

		case *lnrpc.OpenStatusUpdate_ChanOpen:
			channelPoint := update.ChanOpen.ChannelPoint

			// A channel point's funding txid can be get/set as a
			// byte slice or a string. In the case it is a string,
			// decode it.
			var txidHash []byte
			switch channelPoint.GetFundingTxid().(type) {
			case *lnrpc.ChannelPoint_FundingTxidBytes:
				txidHash = channelPoint.GetFundingTxidBytes()
			case *lnrpc.ChannelPoint_FundingTxidStr:
				s := channelPoint.GetFundingTxidStr()
				h, err := chainhash.NewHashFromStr(s)
				if err != nil {
					return err
				}

				txidHash = h[:]
			}

			txid, err := chainhash.NewHash(txidHash)
			if err != nil {
				return err
			}

			index := channelPoint.OutputIndex
			printJSONToWriter(writer, struct {
				ChannelPoint string `json:"channel_point"`
			}{
				ChannelPoint: fmt.Sprintf("%v:%v", txid, index),
			},
			)
		}
	}
}

// TODO(roasbeef): also allow short relative channel ID.

var closeChannelCommand = cli.Command{
	Name:  "closechannel",
	Usage: "Close an existing channel.",
	Description: `
	Close an existing channel. The channel can be closed either cooperatively, 
	or unilaterally (--force).
	
	A unilateral channel closure means that the latest commitment
	transaction will be broadcast to the network. As a result, any settled
	funds will be time locked for a few blocks before they can be swept int
	lnd's wallet.

	In the case of a cooperative closure, One can manually set the fee to
	be used for the closing transaction via either the --conf_target or
	--sat_per_byte arguments. This will be the starting value used during
	fee negotiation.  This is optional.`,
	ArgsUsage: "funding_txid [output_index [time_limit]]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "funding_txid",
			Usage: "the txid of the channel's funding transaction",
		},
		cli.IntFlag{
			Name: "output_index",
			Usage: "the output index for the funding output of the funding " +
				"transaction",
		},
		cli.StringFlag{
			Name: "time_limit",
			Usage: "a relative deadline afterwhich the attempt should be " +
				"abandoned",
		},
		cli.BoolFlag{
			Name: "force",
			Usage: "after the time limit has passed, attempt an " +
				"uncooperative closure",
		},
		cli.BoolFlag{
			Name:  "block",
			Usage: "block until the channel is closed",
		},
		cli.Int64Flag{
			Name: "conf_target",
			Usage: "(optional) the number of blocks that the " +
				"transaction *should* confirm in, will be " +
				"used for fee estimation",
		},
		cli.Int64Flag{
			Name: "sat_per_byte",
			Usage: "(optional) a manual fee expressed in " +
				"sat/byte that should be used when crafting " +
				"the transaction",
		},
	},
	Action: actionDecoratorWithClient(closeChannel),
}

func closeChannel(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)

	// Show command help if no arguments provided
	if !ext.ArgsPresent() {
		cli.ShowCommandHelp(ctx, "closechannel")
		return nil
	}

	// TODO(roasbeef): implement time deadline within server
	req := &lnrpc.CloseChannelRequest{
		ChannelPoint: &lnrpc.ChannelPoint{},
		Force:        ext.BoolFlag("force"),
		TargetConf:   int32(ext.Int64Flag("conf_target")),
		SatPerByte:   ext.Int64Flag("sat_per_byte"),
	}

	txid, err := ext.StringArg("funding_txid")
	if err != nil {
		return err
	}

	req.ChannelPoint.FundingTxid = &lnrpc.ChannelPoint_FundingTxidStr{
		FundingTxidStr: txid,
	}

	index, err := ext.Int64ArgWithDefault("output_index", 0)
	if err != nil {
		return err
	}

	req.ChannelPoint.OutputIndex = uint32(index)

	ctxb := context.Background()
	stream, err := client.CloseChannel(ctxb, req)
	if err != nil {
		return err
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		switch update := resp.Update.(type) {
		case *lnrpc.CloseStatusUpdate_ClosePending:
			closingHash := update.ClosePending.Txid
			txid, err := chainhash.NewHash(closingHash)
			if err != nil {
				return err
			}

			printJSONToWriter(writer, struct {
				ClosingTXID string `json:"closing_txid"`
			}{
				ClosingTXID: txid.String(),
			})

			if !ext.BoolFlag("block") {
				return nil
			}

		case *lnrpc.CloseStatusUpdate_ChanClose:
			closingHash := update.ChanClose.ClosingTxid
			txid, err := chainhash.NewHash(closingHash)
			if err != nil {
				return err
			}

			printJSONToWriter(writer, struct {
				ClosingTXID string `json:"closing_txid"`
			}{
				ClosingTXID: txid.String(),
			})
		}
	}
}

var listPeersCommand = cli.Command{
	Name:   "listpeers",
	Usage:  "List all active, currently connected peers.",
	Action: actionDecoratorWithClient(listPeers),
}

func listPeers(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()
	req := &lnrpc.ListPeersRequest{}
	resp, err := client.ListPeers(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var createCommand = cli.Command{
	Name:   "create",
	Usage:  "Used to set the wallet password at lnd startup",
	Action: actionDecorator(create),
}

func create(ctx *cli.Context) error {
	ctxb := context.Background()
	client, cleanUp := getWalletUnlockerClient(ctx)
	defer cleanUp()

	fmt.Printf("Input wallet password: ")
	pw1, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Println()

	fmt.Printf("Confirm wallet password: ")
	pw2, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Println()

	if !bytes.Equal(pw1, pw2) {
		return fmt.Errorf("passwords don't match")
	}

	req := &lnrpc.CreateWalletRequest{
		Password: pw1,
	}
	_, err = client.CreateWallet(ctxb, req)
	if err != nil {
		return err
	}

	return nil
}

var unlockCommand = cli.Command{
	Name:   "unlock",
	Usage:  "Unlock encrypted wallet at lnd startup",
	Action: actionDecorator(unlock),
}

func unlock(ctx *cli.Context) error {
	ctxb := context.Background()
	client, cleanUp := getWalletUnlockerClient(ctx)
	defer cleanUp()

	fmt.Printf("Input wallet password: ")
	pw, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Println()

	req := &lnrpc.UnlockWalletRequest{
		Password: pw,
	}
	_, err = client.UnlockWallet(ctxb, req)
	if err != nil {
		return err
	}

	return nil
}

var walletBalanceCommand = cli.Command{
	Name:  "walletbalance",
	Usage: "Compute and display the wallet's current balance",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "witness_only",
			Usage: "if only witness outputs should be considered when " +
				"calculating the wallet's balance",
		},
	},
	Action: actionDecoratorWithClient(walletBalance),
}

func walletBalance(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)
	ctxb := context.Background()

	req := &lnrpc.WalletBalanceRequest{
		WitnessOnly: ext.BoolFlag("witness_only"),
	}
	resp, err := client.WalletBalance(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var channelBalanceCommand = cli.Command{
	Name:   "channelbalance",
	Usage:  "Returns the sum of the total available channel balance across all open channels",
	Action: actionDecoratorWithClient(channelBalance),
}

func channelBalance(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	req := &lnrpc.ChannelBalanceRequest{}
	resp, err := client.ChannelBalance(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var getInfoCommand = cli.Command{
	Name:   "getinfo",
	Usage:  "Returns basic information related to the active daemon",
	Action: actionDecoratorWithClient(getInfo),
}

func getInfo(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	req := &lnrpc.GetInfoRequest{}
	resp, err := client.GetInfo(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var pendingChannelsCommand = cli.Command{
	Name:  "pendingchannels",
	Usage: "Display information pertaining to pending channels",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "open, o",
			Usage: "display the status of new pending channels",
		},
		cli.BoolFlag{
			Name:  "close, c",
			Usage: "display the status of channels being closed",
		},
		cli.BoolFlag{
			Name: "all, a",
			Usage: "display the status of channels in the " +
				"process of being opened or closed",
		},
	},
	Action: actionDecoratorWithClient(pendingChannels),
}

func pendingChannels(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	req := &lnrpc.PendingChannelsRequest{}
	resp, err := client.PendingChannels(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)

	return nil
}

var listChannelsCommand = cli.Command{
	Name:  "listchannels",
	Usage: "List all open channels",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "active_only, a",
			Usage: "only list channels which are currently active",
		},
	},
	Action: actionDecoratorWithClient(listChannels),
}

func listChannels(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	req := &lnrpc.ListChannelsRequest{}
	resp, err := client.ListChannels(ctxb, req)
	if err != nil {
		return err
	}

	// TODO(roasbeef): defer close the client for the all

	printRespJSONToWriter(writer, resp)

	return nil
}

var sendPaymentCommand = cli.Command{
	Name:  "sendpayment",
	Usage: "Send a payment over lightning",
	Description: `
	Send a payment over Lightning. One can either specify the full
	parameters of the payment, or just use a payment request which encodes
	all the payment details.

	If payment isn't manually specified, then only a payment request needs
	to be passed using the --pay_req argument.

	If the payment *is* manually specified, then all four alternative
	arguments need to be specified in order to complete the payment:
	    * --dest=N
	    * --amt=A
	    * --final_cltv_delta=T
	    * --payment_hash=H

	The --debug_send flag is provided for usage *purely* in test
	environments. If specified, then the payment hash isn't required, as
	it'll use the hash of all zeroes. This mode allows one to quickly test
	payment connectivity without having to create an invoice at the
	destination.
	`,
	ArgsUsage: "dest amt payment_hash final_cltv_delta | --pay_req=[payment request]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "dest, d",
			Usage: "the compressed identity pubkey of the " +
				"payment recipient",
		},
		cli.Int64Flag{
			Name:  "amt, a",
			Usage: "number of satoshis to send",
		},
		cli.StringFlag{
			Name:  "payment_hash, r",
			Usage: "the hash to use within the payment's HTLC",
		},
		cli.BoolFlag{
			Name:  "debug_send",
			Usage: "use the debug rHash when sending the HTLC",
		},
		cli.StringFlag{
			Name:  "pay_req",
			Usage: "a zpay32 encoded payment request to fulfill",
		},
		cli.Int64Flag{
			Name:  "final_cltv_delta",
			Usage: "the number of blocks the last hop has to reveal the preimage",
		},
	},
	Action: actionDecoratorWithClient(sendPayment),
}

func sendPayment(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)

	// Show command help if no arguments provided
	if !ext.ArgsPresent() {
		cli.ShowCommandHelp(ctx, "sendpayment")
		return nil
	}

	var req *lnrpc.SendRequest
	if ctx.IsSet("pay_req") {
		req = &lnrpc.SendRequest{
			PaymentRequest: ext.StringFlag("pay_req"),
			Amt:            ext.Int64Flag("amt"),
		}
	} else {
		ext := cmd.NewArgExtractor(ctx)
		destNode, err := ext.HexArg("dest")
		if err != nil {
			return err
		}

		if len(destNode) != 33 {
			return fmt.Errorf("dest node pubkey must be exactly 33 bytes, is "+
				"instead: %v", len(destNode))
		}

		amount, err := ext.Int64ArgWithDefault("amt", 0)
		if err != nil {
			return err
		}

		req = &lnrpc.SendRequest{
			Dest: destNode,
			Amt:  amount,
		}

		if ext.BoolFlag("debug_send") &&
			(ext.IsFlagSet("payment_hash") || ext.PositionalArgsPresent()) {

			return ErrUnnecessaryArgumentForDebugSend
		} else if !ext.BoolFlag("debug_send") {
			var rHash []byte

			rHash, err = ext.HexArg("payment_hash")
			if err != nil {
				return err
			}

			if len(rHash) != 32 {
				return fmt.Errorf("payment hash must be exactly 32 "+
					"bytes, is instead %v", len(rHash))
			}
			req.PaymentHash = rHash

			var finalCltvDelta int64
			finalCltvDelta, err = ext.Int64ArgWithDefault("final_cltv_delta", 0)
			if err != nil {
				return err
			}

			req.FinalCltvDelta = int32(finalCltvDelta)
		}
	}

	return sendPaymentRequest(ctx, client, writer, req)
}

func sendPaymentRequest(
	ctx *cli.Context,
	client lnrpc.LightningClient,
	writer io.Writer,
	req *lnrpc.SendRequest) error {

	paymentStream, err := client.SendPayment(context.Background())
	if err != nil {
		return err
	}

	if err := paymentStream.Send(req); err != nil {
		return err
	}

	resp, err := paymentStream.Recv()
	if err != nil {
		return err
	}

	paymentStream.CloseSend()

	printJSONToWriter(writer, struct {
		E string       `json:"payment_error"`
		P string       `json:"payment_preimage"`
		R *lnrpc.Route `json:"payment_route"`
	}{
		E: resp.PaymentError,
		P: hex.EncodeToString(resp.PaymentPreimage),
		R: resp.PaymentRoute,
	})

	return nil
}

var payInvoiceCommand = cli.Command{
	Name:      "payinvoice",
	Usage:     "Pay an invoice over lightning",
	ArgsUsage: "pay_req",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pay_req",
			Usage: "a zpay32 encoded payment request to fulfill",
		},
		cli.Int64Flag{
			Name: "amt",
			Usage: "(optional) number of satoshis to fulfill the " +
				"invoice",
		},
	},
	Action: actionDecoratorWithClient(payInvoice),
}

func payInvoice(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)
	payReq, err := ext.StringArg("pay_req")
	if err != nil {
		return err
	}

	req := &lnrpc.SendRequest{
		PaymentRequest: payReq,
		Amt:            ext.Int64Flag("amt"),
	}

	return sendPaymentRequest(ctx, client, writer, req)
}

var addInvoiceCommand = cli.Command{
	Name:  "addinvoice",
	Usage: "Add a new invoice.",
	Description: `
	Add a new invoice, expressing intent for a future payment.

	Invoices without an amount can be created by not supplying any
	parameters or providing an amount of 0. These invoices allow the payee
	to specify the amount of satoshis they wish to send.`,
	ArgsUsage: "value preimage",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "memo",
			Usage: "a description of the payment to attach along " +
				"with the invoice (default=\"\")",
		},
		cli.StringFlag{
			Name:  "receipt",
			Usage: "an optional cryptographic receipt of payment",
		},
		cli.StringFlag{
			Name: "preimage",
			Usage: "the hex-encoded preimage (32 byte) which will " +
				"allow settling an incoming HTLC payable to this " +
				"preimage. If not set, a random preimage will be " +
				"created.",
		},
		cli.Int64Flag{
			Name:  "amt",
			Usage: "the amt of satoshis in this invoice",
		},
		cli.StringFlag{
			Name: "description_hash",
			Usage: "SHA-256 hash of the description of the payment. " +
				"Used if the purpose of payment cannot naturally " +
				"fit within the memo. If provided this will be " +
				"used instead of the description(memo) field in " +
				"the encoded invoice.",
		},
		cli.StringFlag{
			Name: "fallback_addr",
			Usage: "fallback on-chain address that can be used in " +
				"case the lightning payment fails",
		},
		cli.Int64Flag{
			Name: "expiry",
			Usage: "the invoice's expiry time in seconds. If not " +
				"specified an expiry of 3600 seconds (1 hour) " +
				"is implied.",
		},
	},
	Action: actionDecoratorWithClient(addInvoice),
}

func addInvoice(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	var (
		preimage []byte
		descHash []byte
		receipt  []byte
	)

	ext := cmd.NewArgExtractor(ctx)
	amt, err := ext.Int64Arg("amt")
	if err != nil {
		return err
	}

	preimage, err = ext.HexArg("preimage")
	if err != nil {
		return err
	}

	descHash, err = hex.DecodeString(ext.StringFlag("description_hash"))
	if err != nil {
		return fmt.Errorf("unable to parse description_hash: %v", err)
	}

	receipt, err = hex.DecodeString(ext.StringFlag("receipt"))
	if err != nil {
		return fmt.Errorf("unable to parse receipt: %v", err)
	}

	invoice := &lnrpc.Invoice{
		Memo:            ext.StringFlag("memo"),
		Receipt:         receipt,
		RPreimage:       preimage,
		Value:           amt,
		DescriptionHash: descHash,
		FallbackAddr:    ext.StringFlag("fallback_addr"),
		Expiry:          ext.Int64Flag("expiry"),
	}

	resp, err := client.AddInvoice(context.Background(), invoice)
	if err != nil {
		return err
	}

	printJSONToWriter(writer, struct {
		RHash  string `json:"r_hash"`
		PayReq string `json:"pay_req"`
	}{
		RHash:  hex.EncodeToString(resp.RHash),
		PayReq: resp.PaymentRequest,
	})

	return nil
}

var lookupInvoiceCommand = cli.Command{
	Name:      "lookupinvoice",
	Usage:     "Lookup an existing invoice by its payment hash.",
	ArgsUsage: "rhash",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "rhash",
			Usage: "the 32 byte payment hash of the invoice to query for, the hash " +
				"should be a hex-encoded string",
		},
	},
	Action: actionDecoratorWithClient(lookupInvoice),
}

func lookupInvoice(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)
	rHash, err := ext.HexArg("rhash")
	if err != nil {
		return err
	}

	req := &lnrpc.PaymentHash{
		RHash: rHash,
	}

	invoice, err := client.LookupInvoice(context.Background(), req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, invoice)

	return nil
}

var listInvoicesCommand = cli.Command{
	Name:  "listinvoices",
	Usage: "List all invoices currently stored.",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "pending_only",
			Usage: "toggles if all invoices should be returned, or only " +
				"those that are currently unsettled",
		},
	},
	Action: actionDecoratorWithClient(listInvoices),
}

func listInvoices(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)
	req := &lnrpc.ListInvoiceRequest{
		PendingOnly: ext.BoolFlag("pending_only"),
	}

	invoices, err := client.ListInvoices(context.Background(), req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, invoices)

	return nil
}

var describeGraphCommand = cli.Command{
	Name: "describegraph",
	Description: "Prints a human readable version of the known channel " +
		"graph from the PoV of the node",
	Usage: "Describe the network graph",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "render",
			Usage: "If set, then an image of graph will be generated and displayed. The generated image is stored within the current directory with a file name of 'graph.svg'",
		},
	},
	Action: actionDecoratorWithClient(describeGraph),
}

func describeGraph(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	req := &lnrpc.ChannelGraphRequest{}

	graph, err := client.DescribeGraph(context.Background(), req)
	if err != nil {
		return err
	}

	ext := cmd.NewArgExtractor(ctx)
	// If the draw flag is on, then we'll use the 'dot' command to create a
	// visualization of the graph itself.
	if ext.BoolFlag("render") {
		return drawChannelGraph(graph)
	}

	printRespJSONToWriter(writer, graph)
	return nil
}

// normalizeFunc is a factory function which returns a function that normalizes
// the capacity of of edges within the graph. The value of the returned
// function can be used to either plot the capacities, or to use a weight in a
// rendering of the graph.
func normalizeFunc(edges []*lnrpc.ChannelEdge, scaleFactor float64) func(int64) float64 {
	var (
		min float64 = math.MaxInt64
		max float64
	)

	for _, edge := range edges {
		// In order to obtain saner values, we reduce the capacity of a
		// channel to its base 2 logarithm.
		z := math.Log2(float64(edge.Capacity))

		if z < min {
			min = z
		}
		if z > max {
			max = z
		}
	}

	return func(x int64) float64 {
		y := math.Log2(float64(x))

		// TODO(roasbeef): results in min being zero
		return (y - min) / (max - min) * scaleFactor
	}
}

func drawChannelGraph(graph *lnrpc.ChannelGraph) error {
	// First we'll create a temporary file that we'll write the compiled
	// string that describes our graph in the dot format to.
	tempDotFile, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}
	defer os.Remove(tempDotFile.Name())

	// Next, we'll create (or re-create) the file that the final graph
	// image will be written to.
	imageFile, err := os.Create("graph.svg")
	if err != nil {
		return err
	}

	// With our temporary files set up, we'll initialize the graphviz
	// object that we'll use to draw our graph.
	graphName := "LightningNetwork"
	graphCanvas := gographviz.NewGraph()
	graphCanvas.SetName(graphName)
	graphCanvas.SetDir(false)

	const numKeyChars = 10

	truncateStr := func(k string, n uint) string {
		return k[:n]
	}

	// For each node within the graph, we'll add a new vertex to the graph.
	for _, node := range graph.Nodes {
		// Rather than using the entire hex-encoded string, we'll only
		// use the first 10 characters. We also add a prefix of "Z" as
		// graphviz is unable to parse the compressed pubkey as a
		// non-integer.
		//
		// TODO(roasbeef): should be able to get around this?
		nodeID := fmt.Sprintf(`"%v"`, truncateStr(node.PubKey, numKeyChars))

		attrs := gographviz.Attrs{}

		if node.Color != "" {
			attrs["color"] = fmt.Sprintf(`"%v"`, node.Color)
		}

		graphCanvas.AddNode(graphName, nodeID, attrs)
	}

	normalize := normalizeFunc(graph.Edges, 3)

	// Similarly, for each edge we'll add an edge between the corresponding
	// nodes added to the graph above.
	for _, edge := range graph.Edges {
		// Once again, we add a 'Z' prefix so we're compliant with the
		// dot grammar.
		src := fmt.Sprintf(`"%v"`, truncateStr(edge.Node1Pub, numKeyChars))
		dest := fmt.Sprintf(`"%v"`, truncateStr(edge.Node2Pub, numKeyChars))

		// The weight for our edge will be the total capacity of the
		// channel, in BTC.
		// TODO(roasbeef): can also factor in the edges time-lock delta
		// and fee information
		amt := btcutil.Amount(edge.Capacity).ToBTC()
		edgeWeight := strconv.FormatFloat(amt, 'f', -1, 64)

		// The label for each edge will simply be a truncated version
		// of its channel ID.
		chanIDStr := strconv.FormatUint(edge.ChannelId, 10)
		edgeLabel := fmt.Sprintf(`"cid:%v"`, truncateStr(chanIDStr, 7))

		// We'll also use a normalized version of the channels'
		// capacity in satoshis in order to modulate the "thickness" of
		// the line that creates the edge within the graph.
		normalizedCapacity := normalize(edge.Capacity)
		edgeThickness := strconv.FormatFloat(normalizedCapacity, 'f', -1, 64)

		// If there's only a single channel in the graph, then we'll
		// just set the edge thickness to 1 for everything.
		if math.IsNaN(normalizedCapacity) {
			edgeThickness = "1"
		}

		// TODO(roasbeef): color code based on percentile capacity
		graphCanvas.AddEdge(src, dest, false, gographviz.Attrs{
			"penwidth": edgeThickness,
			"weight":   edgeWeight,
			"label":    edgeLabel,
		})
	}

	// With the declarative generation of the graph complete, we now write
	// the dot-string description of the graph
	graphDotString := graphCanvas.String()
	if _, err := tempDotFile.WriteString(graphDotString); err != nil {
		return err
	}
	if err := tempDotFile.Sync(); err != nil {
		return err
	}

	var errBuffer bytes.Buffer

	// Once our dot file has been written to disk, we can use the dot
	// command itself to generate the drawn rendering of the graph
	// described.
	drawCmd := exec.Command("dot", "-T"+"svg", "-o"+imageFile.Name(),
		tempDotFile.Name())
	drawCmd.Stderr = &errBuffer
	if err := drawCmd.Run(); err != nil {
		fmt.Println("error rendering graph: ", errBuffer.String())
		fmt.Println("dot: ", graphDotString)

		return err
	}

	errBuffer.Reset()

	// Finally, we'll open the drawn graph to display to the user.
	openCmd := exec.Command("open", imageFile.Name())
	openCmd.Stderr = &errBuffer
	if err := openCmd.Run(); err != nil {
		fmt.Println("error opening rendered graph image: ",
			errBuffer.String())
		return err
	}

	return nil
}

var listPaymentsCommand = cli.Command{
	Name:   "listpayments",
	Usage:  "List all outgoing payments",
	Action: actionDecoratorWithClient(listPayments),
}

func listPayments(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	req := &lnrpc.ListPaymentsRequest{}

	payments, err := client.ListPayments(context.Background(), req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, payments)
	return nil
}

var getChanInfoCommand = cli.Command{
	Name:  "getchaninfo",
	Usage: "Get the state of a channel",
	Description: "Prints out the latest authenticated state for a " +
		"particular channel",
	ArgsUsage: "chan_id",
	Flags: []cli.Flag{
		cli.Int64Flag{
			Name:  "chan_id",
			Usage: "the 8-byte compact channel ID to query for",
		},
	},
	Action: actionDecoratorWithClient(getChanInfo),
}

func getChanInfo(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	chanID, err := ext.Int64Arg("chan_id")
	if err != nil {
		return err
	}

	req := &lnrpc.ChanInfoRequest{
		ChanId: uint64(chanID),
	}

	chanInfo, err := client.GetChanInfo(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, chanInfo)
	return nil
}

var getNodeInfoCommand = cli.Command{
	Name:  "getnodeinfo",
	Usage: "Get information on a specific node.",
	Description: "Prints out the latest authenticated node state for an " +
		"advertised node",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "pub_key",
			Usage: "the 33-byte hex-encoded compressed public of the target " +
				"node",
		},
	},
	Action: actionDecoratorWithClient(getNodeInfo),
}

func getNodeInfo(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	pubKey, err := ext.StringArg("pub_key")
	if err != nil {
		return err
	}

	req := &lnrpc.NodeInfoRequest{
		PubKey: pubKey,
	}

	nodeInfo, err := client.GetNodeInfo(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, nodeInfo)
	return nil
}

var queryRoutesCommand = cli.Command{
	Name:        "queryroutes",
	Usage:       "Query a route to a destination.",
	Description: "Queries the channel router for a potential path to the destination that has sufficient flow for the amount including fees",
	ArgsUsage:   "dest amt",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "dest",
			Usage: "the 33-byte hex-encoded public key for the payment " +
				"destination",
		},
		cli.Int64Flag{
			Name:  "amt",
			Usage: "the amount to send expressed in satoshis",
		},
		cli.Int64Flag{
			Name:  "num_max_routes",
			Usage: "the max number of routes to be returned (default: 10)",
			Value: 10,
		},
	},
	Action: actionDecoratorWithClient(queryRoutes),
}

func queryRoutes(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	dest, err := ext.StringArg("dest")
	if err != nil {
		return err
	}

	var amt int64
	amt, err = ext.Int64Arg("amt")
	if err != nil {
		return err
	}

	req := &lnrpc.QueryRoutesRequest{
		PubKey:    dest,
		Amt:       amt,
		NumRoutes: int32(ext.Int64Flag("num_max_routes")),
	}

	route, err := client.QueryRoutes(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, route)
	return nil
}

var getNetworkInfoCommand = cli.Command{
	Name:  "getnetworkinfo",
	Usage: "Getnetworkinfo",
	Description: "Returns a set of statistics pertaining to the known channel " +
		"graph",
	Action: actionDecoratorWithClient(getNetworkInfo),
}

func getNetworkInfo(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	req := &lnrpc.NetworkInfoRequest{}

	netInfo, err := client.GetNetworkInfo(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, netInfo)
	return nil
}

var debugLevelCommand = cli.Command{
	Name:  "debuglevel",
	Usage: "Set the debug level.",
	Description: `Logging level for all subsystems {trace, debug, info, warn, error, critical}
	You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems
	
	Use show to list available subsystems`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "show",
			Usage: "if true, then the list of available sub-systems will be printed out",
		},
		cli.StringFlag{
			Name:  "level",
			Usage: "the level specification to target either a coarse logging level, or granular set of specific sub-systems with logging levels for each",
		},
	},
	Action: actionDecoratorWithClient(debugLevel),
}

func debugLevel(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ext := cmd.NewArgExtractor(ctx)

	ctxb := context.Background()
	req := &lnrpc.DebugLevelRequest{
		Show:      ext.BoolFlag("show"),
		LevelSpec: ext.StringFlag("level"),
	}

	resp, err := client.DebugLevel(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var decodePayReqCommand = cli.Command{
	Name:        "decodepayreq",
	Usage:       "Decode a payment request.",
	Description: "Decode the passed payment request revealing the destination, payment hash and value of the payment request",
	ArgsUsage:   "pay_req",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pay_req",
			Usage: "the bech32 encoded payment request",
		},
	},
	Action: actionDecoratorWithClient(decodePayReq),
}

func decodePayReq(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	payreq, err := ext.StringArg("pay_req")
	if err != nil {
		return err
	}

	resp, err := client.DecodePayReq(ctxb, &lnrpc.PayReqString{
		PayReq: payreq,
	})
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var listChainTxnsCommand = cli.Command{
	Name:        "listchaintxns",
	Usage:       "List transactions from the wallet.",
	Description: "List all transactions an address of the wallet was involved in.",
	Action:      actionDecoratorWithClient(listChainTxns),
}

func listChainTxns(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	resp, err := client.GetTransactions(ctxb, &lnrpc.GetTransactionsRequest{})

	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var stopCommand = cli.Command{
	Name:  "stop",
	Usage: "Stop and shutdown the daemon.",
	Description: `
	Gracefully stop all daemon subsystems before stopping the daemon itself. 
	This is equivalent to stopping it using CTRL-C.`,
	Action: actionDecoratorWithClient(stopDaemon),
}

func stopDaemon(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	_, err := client.StopDaemon(ctxb, &lnrpc.StopRequest{})
	if err != nil {
		return err
	}

	return nil
}

var signMessageCommand = cli.Command{
	Name:      "signmessage",
	Usage:     "Sign a message with the node's private key",
	ArgsUsage: "msg",
	Description: `
	Sign msg with the resident node's private key. 
	Returns the signature as a zbase32 string. 
	
	Positional arguments and flags can be used interchangeably but not at the same time!`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "msg",
			Usage: "the message to sign",
		},
	},
	Action: actionDecoratorWithClient(signMessage),
}

func signMessage(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	msg, err := ext.StringArg("msg")
	if err != nil {
		return err
	}

	resp, err := client.SignMessage(
		ctxb, &lnrpc.SignMessageRequest{Msg: []byte(msg)})
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var verifyMessageCommand = cli.Command{
	Name:      "verifymessage",
	Usage:     "Verify a message signed with the signature",
	ArgsUsage: "msg signature",
	Description: `
	Verify that the message was signed with a properly-formed signature
	The signature must be zbase32 encoded and signed with the private key of
	an active node in the resident node's channel database.

	Positional arguments and flags can be used interchangeably but not at the same time!`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "msg",
			Usage: "the message to verify",
		},
		cli.StringFlag{
			Name:  "sig",
			Usage: "the zbase32 encoded signature of the message",
		},
	},
	Action: actionDecoratorWithClient(verifyMessage),
}

func verifyMessage(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	ext := cmd.NewArgExtractor(ctx)
	msg, err := ext.StringArg("msg")
	if err != nil {
		return err
	}

	var sig string
	sig, err = ext.StringArg("sig")
	if err != nil {
		return err
	}

	req := &lnrpc.VerifyMessageRequest{Msg: []byte(msg), Signature: sig}
	resp, err := client.VerifyMessage(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var feeReportCommand = cli.Command{
	Name:  "feereport",
	Usage: "Display the current fee policies of all active channels",
	Description: ` 
	Returns the current fee policies of all active channels.
	Fee policies can be updated using the updatechanpolicy command.`,
	Action: actionDecoratorWithClient(feeReport),
}

func feeReport(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	req := &lnrpc.FeeReportRequest{}
	resp, err := client.FeeReport(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var updateChannelPolicyCommand = cli.Command{
	Name:      "updatechanpolicy",
	Usage:     "Update the channel policy for all channels, or a single channel",
	ArgsUsage: "base_fee_msat fee_rate time_lock_delta [channel_point]",
	Description: `
	Updates the channel policy for all channels, or just a particular channel
	identified by its channel point. The update will be committed, and
	broadcast to the rest of the network within the next batch.
	Channel points are encoded as: funding_txid:output_index`,
	Flags: []cli.Flag{
		cli.Int64Flag{
			Name: "base_fee_msat",
			Usage: "the base fee in milli-satoshis that will " +
				"be charged for each forwarded HTLC, regardless " +
				"of payment size",
		},
		cli.StringFlag{
			Name: "fee_rate",
			Usage: "the fee rate that will be charged " +
				"proportionally based on the value of each " +
				"forwarded HTLC, the lowest possible rate is 0.000001",
		},
		cli.Int64Flag{
			Name: "time_lock_delta",
			Usage: "the CLTV delta that will be applied to all " +
				"forwarded HTLCs",
		},
		cli.StringFlag{
			Name: "chan_point",
			Usage: "The channel whose fee policy should be " +
				"updated, if nil the policies for all channels " +
				"will be updated. Takes the form of: txid:output_index",
		},
	},
	Action: actionDecoratorWithClient(updateChannelPolicy),
}

func updateChannelPolicy(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	var (
		baseFee       int64
		feeRate       float64
		timeLockDelta int64
		err           error
	)

	ext := cmd.NewArgExtractor(ctx)
	baseFee, err = ext.Int64Arg("base_fee_msat")
	if err != nil {
		return err
	}

	feeRate, err = ext.Float64Arg("fee_rate")
	if err != nil {
		return err
	}

	timeLockDelta, err = ext.Int64Arg("time_lock_delta")
	if err != nil {
		return err
	}

	var (
		chanPoint    *lnrpc.ChannelPoint
		chanPointStr string
	)

	chanPointStr = ext.StringArgWithDefault("chan_point", "")

	if chanPointStr != "" {
		split := strings.Split(chanPointStr, ":")
		if len(split) != 2 {
			return ErrBadChanPointFormat
		}

		index, err := strconv.ParseInt(split[1], 10, 32)
		if err != nil {
			return fmt.Errorf("unable to decode output index: %v", err)
		}

		chanPoint = &lnrpc.ChannelPoint{
			FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
				FundingTxidStr: split[0],
			},
			OutputIndex: uint32(index),
		}
	}

	req := &lnrpc.PolicyUpdateRequest{
		BaseFeeMsat:   baseFee,
		FeeRate:       feeRate,
		TimeLockDelta: uint32(timeLockDelta),
	}

	if chanPoint != nil {
		req.Scope = &lnrpc.PolicyUpdateRequest_ChanPoint{
			ChanPoint: chanPoint,
		}
	} else {
		req.Scope = &lnrpc.PolicyUpdateRequest_Global{
			Global: true,
		}
	}

	resp, err := client.UpdateChannelPolicy(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}
