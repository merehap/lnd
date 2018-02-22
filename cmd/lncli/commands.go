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
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcutil"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TODO(roasbeef): cli logic for supporting both positional and unix style
// arguments.

// TODO(roasbeef): expose all fee conf targets

var (
	// ErrBadAddressFormat occurs if a user provides a bad LightningAddress.
	ErrBadAddressFormat = fmt.Errorf(
		"target address expected in format: pubkey@host:port")
	// ErrMissingPubKey is used when the user fails to supply a pubkey.
	ErrMissingPubKey = fmt.Errorf("must specify target public key")
	// ErrDuplicatePeerSpecifiers occurs if both peer_id and node_key
	// are set at the same time.
	ErrDuplicatePeerSpecifiers = fmt.Errorf("both peer_id and node_key " +
		"cannot be set at the same time, only one can be specified")
	// ErrMissingPeerSpecifiers occurs if neither peer_id nor node_key
	// are specified.
	ErrMissingPeerSpecifiers = fmt.Errorf("node id argument missing")
	// ErrMissingLocalAmount occurs if the local_amt argument is omitted.
	ErrMissingLocalAmount = fmt.Errorf("local amt argument missing")

	// ErrMissingFundingTxid occurs if the funding_txid argument is omitted.
	ErrMissingFundingTxid = fmt.Errorf("funding txid argument missing")

	// ErrMissingPayReq occurs if the pay_req argument is omitted.
	ErrMissingPayReq = fmt.Errorf("pay_req argument missing")

	// ErrMissingDestinationTxid occurs if the dest argument is omitted.
	ErrMissingDestinationTxid = fmt.Errorf("destination txid argument missing")

	// ErrMissingPaymentHash occurs if the payemtn hash is omitted.
	ErrMissingPaymentHash = fmt.Errorf("payment hash argument missing")

	// ErrUnnecessaryArgumentForDebugSend if unnecessary args are specified
	// on a debug send.
	ErrUnnecessaryArgumentForDebugSend = fmt.Errorf("do not provide a payment hash with debug send")

	// ErrMissingAddress occurs if address is omitted.
	ErrMissingAddress = fmt.Errorf("Address argument missing")
	// ErrMissingAmount occurs if amt is omitted.
	ErrMissingAmount = fmt.Errorf("Amount argument missing")

	// ErrMultipleFeeArgs occurs if multiple conflicting ways to specify
	// fees were provided.
	ErrMultipleFeeArgs = fmt.Errorf(
		"either conf_target or sat_per_byte should be set, but not both")
)

func printJSON(resp interface{}) {
	printJSONToWriter(os.Stdout, resp)
}

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

func printRespJSON(resp proto.Message) {
	printRespJSONToWriter(os.Stdout, resp)
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
	Usage:     "generates a new address.",
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

	stringAddrType := ctx.Args().First()

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
	Usage:     "send bitcoin on-chain to an address",
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

	var (
		addr string
		amt  int64
		err  error
	)
	args := ctx.Args()

	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		cli.ShowCommandHelp(ctx, "sendcoins")
		return nil
	}

	if ctx.IsSet("conf_target") && ctx.IsSet("sat_per_byte") {
		return ErrMultipleFeeArgs
	}

	switch {
	case ctx.IsSet("addr"):
		addr = ctx.String("addr")
	case args.Present():
		addr = args.First()
		args = args.Tail()
	default:
		return ErrMissingAddress
	}

	switch {
	case ctx.IsSet("amt"):
		amt = ctx.Int64("amt")
	case args.Present():
		amt, err = strconv.ParseInt(args.First(), 10, 64)
	default:
		return ErrMissingAmount
	}

	if err != nil {
		return fmt.Errorf("unable to decode amount: %v", err)
	}

	ctxb := context.Background()

	req := &lnrpc.SendCoinsRequest{
		Addr:       addr,
		Amount:     amt,
		TargetConf: int32(ctx.Int64("conf_target")),
		SatPerByte: ctx.Int64("sat_per_byte"),
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
	Usage:     "send bitcoin on-chain to multiple addresses.",
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

	jsonMap := ctx.Args().First()
	if err := json.Unmarshal([]byte(jsonMap), &amountToAddr); err != nil {
		return err
	}

	if ctx.IsSet("conf_target") && ctx.IsSet("sat_per_byte") {
		return ErrMultipleFeeArgs
	}

	ctxb := context.Background()

	txid, err := client.SendMany(ctxb, &lnrpc.SendManyRequest{
		AddrToAmount: amountToAddr,
		TargetConf:   int32(ctx.Int64("conf_target")),
		SatPerByte:   ctx.Int64("sat_per_byte"),
	})
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, txid)
	return nil
}

var connectCommand = cli.Command{
	Name:      "connect",
	Usage:     "connect to a remote lnd peer",
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

	ctxb := context.Background()

	targetAddress := ctx.Args().First()
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
		Perm: ctx.Bool("perm"),
	}

	lnid, err := client.ConnectPeer(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, lnid)
	return nil
}

var disconnectCommand = cli.Command{
	Name:      "disconnect",
	Usage:     "disconnect a remote lnd peer identified by public key",
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

	var pubKey string
	switch {
	case ctx.IsSet("node_key"):
		pubKey = ctx.String("node_key")
	case ctx.Args().Present():
		pubKey = ctx.Args().First()
	default:
		return ErrMissingPubKey
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
	Usage: "Open a channel to an existing peer.",
	Description: `
	Attempt to open a new channel to an existing peer with the key node-key
	optionally blocking until the channel is 'open'.

	The channel will be initialized with local-amt satoshis local and push-amt
	satoshis for the remote node. Once the channel is open, a channelPoint (txid:vout) 
	of the funding output is returned. 

	One can manually set the fee to be used for the funding transaction via either
	the --conf_target or --sat_per_byte arguments. This is optional.
		
	NOTE: peer_id and node_key are mutually exclusive, only one should be used, not both.`,
	ArgsUsage: "node-key local-amt push-amt",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "peer_id",
			Usage: "the relative id of the peer to open a channel with",
		},
		cli.StringFlag{
			Name: "node_key",
			Usage: "the identity public key of the target peer " +
				"serialized in compressed format",
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

	args := ctx.Args()
	var err error

	// Show command help if no arguments provided
	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		cli.ShowCommandHelp(ctx, "openchannel")
		return nil
	}

	if ctx.IsSet("peer_id") && ctx.IsSet("node_key") {
		return ErrDuplicatePeerSpecifiers
	}

	req := &lnrpc.OpenChannelRequest{
		TargetConf:  int32(ctx.Int64("conf_target")),
		SatPerByte:  ctx.Int64("sat_per_byte"),
		MinHtlcMsat: ctx.Int64("min_htlc_msat"),
	}

	switch {
	case ctx.IsSet("peer_id"):
		req.TargetPeerId = int32(ctx.Int("peer_id"))
	case ctx.IsSet("node_key"):
		nodePubHex, err := hex.DecodeString(ctx.String("node_key"))
		if err != nil {
			return fmt.Errorf("unable to decode node public key: %v", err)
		}
		req.NodePubkey = nodePubHex
	case args.Present():
		nodePubHex, err := hex.DecodeString(args.First())
		if err != nil {
			return fmt.Errorf("unable to decode node public key: %v", err)
		}
		args = args.Tail()
		req.NodePubkey = nodePubHex
	default:
		return ErrMissingPeerSpecifiers
	}

	switch {
	case ctx.IsSet("local_amt"):
		req.LocalFundingAmount = int64(ctx.Int("local_amt"))
	case args.Present():
		req.LocalFundingAmount, err = strconv.ParseInt(args.First(), 10, 64)
		if err != nil {
			return fmt.Errorf("unable to decode local amt: %v", err)
		}
		args = args.Tail()
	default:
		return ErrMissingLocalAmount
	}

	if ctx.IsSet("push_amt") {
		req.PushSat = int64(ctx.Int("push_amt"))
	} else if args.Present() {
		req.PushSat, err = strconv.ParseInt(args.First(), 10, 64)
		if err != nil {
			return fmt.Errorf("unable to decode push amt: %v", err)
		}
	}

	req.Private = ctx.Bool("private")

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

			if !ctx.Bool("block") {
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

	ctxb := context.Background()

	args := ctx.Args()
	var (
		txid string
		err  error
	)

	// Show command help if no arguments provided
	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		cli.ShowCommandHelp(ctx, "closechannel")
		return nil
	}

	// TODO(roasbeef): implement time deadline within server
	req := &lnrpc.CloseChannelRequest{
		ChannelPoint: &lnrpc.ChannelPoint{},
		Force:        ctx.Bool("force"),
		TargetConf:   int32(ctx.Int64("conf_target")),
		SatPerByte:   ctx.Int64("sat_per_byte"),
	}

	switch {
	case ctx.IsSet("funding_txid"):
		txid = ctx.String("funding_txid")
	case args.Present():
		txid = args.First()
		args = args.Tail()
	default:
		return ErrMissingFundingTxid
	}

	req.ChannelPoint.FundingTxid = &lnrpc.ChannelPoint_FundingTxidStr{
		FundingTxidStr: txid,
	}

	switch {
	case ctx.IsSet("output_index"):
		req.ChannelPoint.OutputIndex = uint32(ctx.Int("output_index"))
	case args.Present():
		index, err := strconv.ParseInt(args.First(), 10, 32)
		if err != nil {
			return fmt.Errorf("unable to decode output index: %v", err)
		}
		req.ChannelPoint.OutputIndex = uint32(index)
	default:
		req.ChannelPoint.OutputIndex = 0
	}

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

			if !ctx.Bool("block") {
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
	Usage:  "used to set the wallet password at lnd startup",
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
	Usage:  "unlock encrypted wallet at lnd startup",
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
	Usage: "compute and display the wallet's current balance",
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

	ctxb := context.Background()

	req := &lnrpc.WalletBalanceRequest{
		WitnessOnly: ctx.Bool("witness_only"),
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
	Usage:  "returns the sum of the total available channel balance across all open channels",
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
	Usage:  "returns basic information related to the active daemon",
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
	Usage: "display information pertaining to pending channels",
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
	Usage: "list all open channels",
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
	Usage: "send a payment over lightning",
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

	// Show command help if no arguments provided
	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		cli.ShowCommandHelp(ctx, "sendpayment")
		return nil
	}

	var req *lnrpc.SendRequest
	if ctx.IsSet("pay_req") {
		req = &lnrpc.SendRequest{
			PaymentRequest: ctx.String("pay_req"),
			Amt:            ctx.Int64("amt"),
		}
	} else {
		args := ctx.Args()

		var (
			destNode []byte
			err      error
			amount   int64
		)

		switch {
		case ctx.IsSet("dest"):
			destNode, err = hex.DecodeString(ctx.String("dest"))
		case args.Present():
			destNode, err = hex.DecodeString(args.First())
			args = args.Tail()
		default:
			return ErrMissingDestinationTxid
		}
		if err != nil {
			return err
		}

		if len(destNode) != 33 {
			return fmt.Errorf("dest node pubkey must be exactly 33 bytes, is "+
				"instead: %v", len(destNode))
		}

		if ctx.IsSet("amt") {
			amount = ctx.Int64("amt")
		} else if args.Present() {
			amount, err = strconv.ParseInt(args.First(), 10, 64)
			args = args.Tail()
			if err != nil {
				return fmt.Errorf("unable to decode payment amount: %v", err)
			}
		}

		req = &lnrpc.SendRequest{
			Dest: destNode,
			Amt:  amount,
		}

		if ctx.Bool("debug_send") && (ctx.IsSet("payment_hash") || args.Present()) {
			return ErrUnnecessaryArgumentForDebugSend
		} else if !ctx.Bool("debug_send") {
			var rHash []byte

			switch {
			case ctx.IsSet("payment_hash"):
				rHash, err = hex.DecodeString(ctx.String("payment_hash"))
			case args.Present():
				rHash, err = hex.DecodeString(args.First())
				// TODO(merehap): Bug fix. Add "args = args.Tail()" here.
			default:
				return ErrMissingPaymentHash
			}

			if err != nil {
				return err
			}
			if len(rHash) != 32 {
				return fmt.Errorf("payment hash must be exactly 32 "+
					"bytes, is instead %v", len(rHash))
			}
			req.PaymentHash = rHash

			switch {
			case ctx.IsSet("final_cltv_delta"):
				req.FinalCltvDelta = int32(ctx.Int64("final_cltv_delta"))
			case args.Present():
				delta, err := strconv.ParseInt(args.First(), 10, 64)
				if err != nil {
					return err
				}
				req.FinalCltvDelta = int32(delta)
			}
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
	Usage:     "pay an invoice over lightning",
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
	args := ctx.Args()

	var payReq string

	switch {
	case ctx.IsSet("pay_req"):
		payReq = ctx.String("pay_req")
	case args.Present():
		payReq = args.First()
	default:
		return ErrMissingPayReq
	}

	req := &lnrpc.SendRequest{
		PaymentRequest: payReq,
		Amt:            ctx.Int64("amt"),
	}

	return sendPaymentRequest(ctx, client, writer, req)
}

var addInvoiceCommand = cli.Command{
	Name:  "addinvoice",
	Usage: "add a new invoice.",
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
		amt      int64
		err      error
	)

	args := ctx.Args()

	switch {
	case ctx.IsSet("amt"):
		amt = ctx.Int64("amt")
	case args.Present():
		amt, err = strconv.ParseInt(args.First(), 10, 64)
		args = args.Tail()
		if err != nil {
			return fmt.Errorf("unable to decode amt argument: %v", err)
		}
	}

	switch {
	case ctx.IsSet("preimage"):
		preimage, err = hex.DecodeString(ctx.String("preimage"))
	case args.Present():
		preimage, err = hex.DecodeString(args.First())
	}

	if err != nil {
		return fmt.Errorf("unable to parse preimage: %v", err)
	}

	descHash, err = hex.DecodeString(ctx.String("description_hash"))
	if err != nil {
		return fmt.Errorf("unable to parse description_hash: %v", err)
	}

	receipt, err = hex.DecodeString(ctx.String("receipt"))
	if err != nil {
		return fmt.Errorf("unable to parse receipt: %v", err)
	}

	invoice := &lnrpc.Invoice{
		Memo:            ctx.String("memo"),
		Receipt:         receipt,
		RPreimage:       preimage,
		Value:           amt,
		DescriptionHash: descHash,
		FallbackAddr:    ctx.String("fallback_addr"),
		Expiry:          ctx.Int64("expiry"),
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

	var (
		rHash []byte
		err   error
	)

	switch {
	case ctx.IsSet("rhash"):
		rHash, err = hex.DecodeString(ctx.String("rhash"))
	case ctx.Args().Present():
		rHash, err = hex.DecodeString(ctx.Args().First())
	default:
		return fmt.Errorf("rhash argument missing")
	}

	if err != nil {
		return fmt.Errorf("unable to decode rhash argument: %v", err)
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

	pendingOnly := true
	if !ctx.Bool("pending_only") {
		pendingOnly = false
	}

	req := &lnrpc.ListInvoiceRequest{
		PendingOnly: pendingOnly,
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
	Description: "prints a human readable version of the known channel " +
		"graph from the PoV of the node",
	Usage: "describe the network graph",
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

	// If the draw flag is on, then we'll use the 'dot' command to create a
	// visualization of the graph itself.
	if ctx.Bool("render") {
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
		// channel to it's base 2 logarithm.
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
		// of it's channel ID.
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
	Usage:  "list all outgoing payments",
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
	Usage: "get the state of a channel",
	Description: "prints out the latest authenticated state for a " +
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

	var (
		chanID int64
		err    error
	)

	switch {
	case ctx.IsSet("chan_id"):
		chanID = ctx.Int64("chan_id")
	case ctx.Args().Present():
		chanID, err = strconv.ParseInt(ctx.Args().First(), 10, 64)
	default:
		return fmt.Errorf("chan_id argument missing")
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
	Description: "prints out the latest authenticated node state for an " +
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

	args := ctx.Args()

	var pubKey string
	switch {
	case ctx.IsSet("pub_key"):
		pubKey = ctx.String("pub_key")
	case args.Present():
		pubKey = args.First()
	default:
		return fmt.Errorf("pub_key argument missing")
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
	},
	Action: actionDecoratorWithClient(queryRoutes),
}

func queryRoutes(
	ctx *cli.Context, client lnrpc.LightningClient, writer io.Writer) error {

	ctxb := context.Background()

	var (
		dest string
		amt  int64
		err  error
	)

	args := ctx.Args()

	switch {
	case ctx.IsSet("dest"):
		dest = ctx.String("dest")
	case args.Present():
		dest = args.First()
		args = args.Tail()
	default:
		return fmt.Errorf("dest argument missing")
	}

	switch {
	case ctx.IsSet("amt"):
		amt = ctx.Int64("amt")
	case args.Present():
		amt, err = strconv.ParseInt(args.First(), 10, 64)
		if err != nil {
			return fmt.Errorf("unable to decode amt argument: %v", err)
		}
	default:
		return fmt.Errorf("amt argument missing")
	}

	req := &lnrpc.QueryRoutesRequest{
		PubKey: dest,
		Amt:    amt,
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
	Usage: "getnetworkinfo",
	Description: "returns a set of statistics pertaining to the known channel " +
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

	ctxb := context.Background()
	req := &lnrpc.DebugLevelRequest{
		Show:      ctx.Bool("show"),
		LevelSpec: ctx.String("level"),
	}

	resp, err := client.DebugLevel(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var decodePayReqComamnd = cli.Command{
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

	var payreq string

	switch {
	case ctx.IsSet("pay_req"):
		payreq = ctx.String("pay_req")
	case ctx.Args().Present():
		payreq = ctx.Args().First()
	default:
		return fmt.Errorf("pay_req argument missing")
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
	Usage:     "sign a message with the node's private key",
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

	var msg []byte

	switch {
	case ctx.IsSet("msg"):
		msg = []byte(ctx.String("msg"))
	case ctx.Args().Present():
		msg = []byte(ctx.Args().First())
	default:
		return fmt.Errorf("msg argument missing")
	}

	resp, err := client.SignMessage(ctxb, &lnrpc.SignMessageRequest{Msg: msg})
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var verifyMessageCommand = cli.Command{
	Name:      "verifymessage",
	Usage:     "verify a message signed with the signature",
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

	var (
		msg []byte
		sig string
	)

	args := ctx.Args()

	switch {
	case ctx.IsSet("msg"):
		msg = []byte(ctx.String("msg"))
	case args.Present():
		msg = []byte(ctx.Args().First())
		args = args.Tail()
	default:
		return fmt.Errorf("msg argument missing")
	}

	switch {
	case ctx.IsSet("sig"):
		sig = ctx.String("sig")
	case args.Present():
		sig = args.First()
	default:
		return fmt.Errorf("signature argument missing")
	}

	req := &lnrpc.VerifyMessageRequest{Msg: msg, Signature: sig}
	resp, err := client.VerifyMessage(ctxb, req)
	if err != nil {
		return err
	}

	printRespJSONToWriter(writer, resp)
	return nil
}

var feeReportCommand = cli.Command{
	Name:  "feereport",
	Usage: "display the current fee policies of all active channels",
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
	Usage:     "update the channel policy for all channels, or a single channel",
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
	args := ctx.Args()

	switch {
	case ctx.IsSet("base_fee_msat"):
		baseFee = ctx.Int64("base_fee_msat")
	case args.Present():
		baseFee, err = strconv.ParseInt(args.First(), 10, 64)
		if err != nil {
			return fmt.Errorf("unable to decode base_fee_msat: %v", err)
		}
		args = args.Tail()
	default:
		return fmt.Errorf("base_fee_msat argument missing")
	}

	switch {
	case ctx.IsSet("fee_rate"):
		feeRate = ctx.Float64("fee_rate")
	case args.Present():
		feeRate, err = strconv.ParseFloat(args.First(), 64)
		if err != nil {
			return fmt.Errorf("unable to decode fee_rate: %v", err)
		}

		args = args.Tail()
	default:
		return fmt.Errorf("fee_rate argument missing")
	}

	switch {
	case ctx.IsSet("time_lock_delta"):
		timeLockDelta = ctx.Int64("time_lock_delta")
	case args.Present():
		timeLockDelta, err = strconv.ParseInt(args.First(), 10, 64)
		if err != nil {
			return fmt.Errorf("unable to decode time_lock_delta: %v",
				err)
		}

		args = args.Tail()
	default:
		return fmt.Errorf("time_lock_delta argument missing")
	}

	var (
		chanPoint    *lnrpc.ChannelPoint
		chanPointStr string
	)

	switch {
	case ctx.IsSet("chan_point"):
		chanPointStr = ctx.String("chan_point")
	case args.Present():
		chanPointStr = args.First()
	}

	if chanPointStr != "" {
		split := strings.Split(chanPointStr, ":")
		if len(split) != 2 {
			return fmt.Errorf("expecting chan_point to be in format of: " +
				"txid:index")
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
