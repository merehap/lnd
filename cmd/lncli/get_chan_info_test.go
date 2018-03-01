package main

import (
	"io"
	"testing"

	"github.com/lightningnetwork/lnd/cmd"
	"github.com/lightningnetwork/lnd/lnrpc"
)

var (
	expectedGetChanInfoResponse = "{\n    " +
		"\"channel_id\": \"0\",\n    " +
		"\"chan_point\": \"\",\n    " +
		"\"last_update\": 0,\n    " +
		"\"node1_pub\": \"\",\n    " +
		"\"node2_pub\": \"\",\n    " +
		"\"capacity\": \"0\",\n    " +
		"\"node1_policy\": null,\n    " +
		"\"node2_policy\": null\n}\n"
)

func TestGetChanInfo(t *testing.T) {
	TestCommandNoError(t, runGetChanInfo,
		[]string{"234"},
		expectedGetChanInfoRequest(),
		expectedGetChanInfoResponse)
}

func TestGetChanInfo_ChanIdFlag(t *testing.T) {
	TestCommandNoError(t, runGetChanInfo,
		[]string{"--chan_id", "234"},
		expectedGetChanInfoRequest(),
		expectedGetChanInfoResponse)
}

func TestGetChanInfo_BadChanId(t *testing.T) {
	TestCommandTextInValidationError(t, runGetChanInfo,
		[]string{"BadChanId"},
		"unable to parse chan_id")
}

func TestGetChanInfo_BadChanIdFlag(t *testing.T) {
	TestCommandTextInResponse(t, runGetChanInfo,
		[]string{"--chan_id", "BadChanId"},
		"Incorrect Usage: invalid value")
}

func TestGetChanInfo_MissingChanId(t *testing.T) {
	TestCommandValidationError(t, runGetChanInfo,
		[]string{},
		&cmd.MissingArgError{"chan_id"})
}

func TestGetChanInfo_RPCError(t *testing.T) {
	TestCommandRPCError(t, runGetChanInfo,
		[]string{PushAmount},
		io.ErrClosedPipe,
		io.ErrClosedPipe)
}

func runGetChanInfo(
	client lnrpc.LightningClient, args []string) (string, error) {

	return RunCommand(
		client, getChanInfoCommand, getChanInfo, "getchaninfo", args)
}

func expectedGetChanInfoRequest() *lnrpc.ChanInfoRequest {
	return &lnrpc.ChanInfoRequest{ChanId: 0xea}
}
