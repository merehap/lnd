package main

import (
	"io"
	"testing"

	"github.com/lightningnetwork/lnd/cmd"
	"github.com/lightningnetwork/lnd/lnrpc"
)

var (
	expectedUpdateChannelPolicyResponse = "{\n\n}\n"
)

func TestUpdateChannelPolicy(t *testing.T) {
	TestCommandNoError(t, runUpdateChannelPolicy,
		[]string{BaseFeeMsat, FeeRate, TimeLockDelta, ChanPoint},
		expectedPolicyUpdateRequest(),
		expectedUpdateChannelPolicyResponse)
}

func TestUpdateChannelPolicy_BaseFeeMsatFlag(t *testing.T) {
	TestCommandNoError(t, runUpdateChannelPolicy,
		[]string{"--base_fee_msat", BaseFeeMsat, FeeRate, TimeLockDelta, ChanPoint},
		expectedPolicyUpdateRequest(),
		expectedUpdateChannelPolicyResponse)
}

func TestUpdateChannelPolicy_FeeRateFlag(t *testing.T) {
	TestCommandNoError(t, runUpdateChannelPolicy,
		[]string{"--fee_rate", FeeRate, BaseFeeMsat, TimeLockDelta, ChanPoint},
		expectedPolicyUpdateRequest(),
		expectedUpdateChannelPolicyResponse)
}

func TestUpdateChannelPolicy_TimeLockDeltaFlag(t *testing.T) {
	TestCommandNoError(t, runUpdateChannelPolicy,
		[]string{"--time_lock_delta", TimeLockDelta, BaseFeeMsat, FeeRate, ChanPoint},
		expectedPolicyUpdateRequest(),
		expectedUpdateChannelPolicyResponse)
}

func TestUpdateChannelPolicy_ChanPointFlag(t *testing.T) {
	TestCommandNoError(t, runUpdateChannelPolicy,
		[]string{"--chan_point", ChanPoint, BaseFeeMsat, FeeRate, TimeLockDelta},
		expectedPolicyUpdateRequest(),
		expectedUpdateChannelPolicyResponse)
}

func TestUpdateChannelPolicy_DefaultChanPoint(t *testing.T) {
	expectedRequest := expectedPolicyUpdateRequest()
	expectedRequest.Scope = &lnrpc.PolicyUpdateRequest_Global{Global: true}

	TestCommandNoError(t, runUpdateChannelPolicy,
		[]string{
			"--base_fee_msat", BaseFeeMsat,
			"--fee_rate", FeeRate,
			"--time_lock_delta", TimeLockDelta},
		expectedRequest,
		expectedUpdateChannelPolicyResponse)
}

func TestUpdateChannelPolicy_NoBaseFeeMsat(t *testing.T) {
	TestCommandValidationError(t, runUpdateChannelPolicy,
		[]string{
			"--fee_rate", FeeRate,
			"--time_lock_delta", TimeLockDelta,
			"--chan_point", ChanPoint},
		&cmd.MissingArgError{"base_fee_msat"})
}

func TestUpdateChannelPolicy_NoFeeRate(t *testing.T) {
	TestCommandValidationError(t, runUpdateChannelPolicy,
		[]string{
			"--base_fee_msat", BaseFeeMsat,
			"--time_lock_delta", TimeLockDelta,
			"--chan_point", ChanPoint},
		&cmd.MissingArgError{"fee_rate"})
}

func TestUpdateChannelPolicy_NoTimeLockDelta(t *testing.T) {
	TestCommandValidationError(t, runUpdateChannelPolicy,
		[]string{
			"--base_fee_msat", BaseFeeMsat,
			"--fee_rate", FeeRate,
			"--chan_point", ChanPoint},
		&cmd.MissingArgError{"time_lock_delta"})
}

func TestUpdateChannelPolicy_BadBaseFeeMsat(t *testing.T) {
	TestCommandTextInValidationError(t, runUpdateChannelPolicy,
		[]string{"BadBaseFeeMsat", FeeRate, TimeLockDelta, ChanPoint},
		"unable to parse base_fee_msat")
}

func TestUpdateChannelPolicy_BadBaseFeeMsatFlag(t *testing.T) {
	TestCommandTextInResponse(t, runUpdateChannelPolicy,
		[]string{"--base_fee_msat", "BadBaseFeeMsat", FeeRate, TimeLockDelta, ChanPoint},
		"updatechanpolicy - Update the channel policy for all channels, or a single channel")
}

func TestUpdateChannelPolicy_BadFeeRate(t *testing.T) {
	TestCommandTextInValidationError(t, runUpdateChannelPolicy,
		[]string{BaseFeeMsat, "BadFeeRate", TimeLockDelta, ChanPoint},
		"unable to parse fee_rate")
}

func TestUpdateChannelPolicy_BadFeeRateFlag(t *testing.T) {
	TestCommandTextInValidationError(t, runUpdateChannelPolicy,
		[]string{"--fee_rate", "BadFeeRate", BaseFeeMsat, TimeLockDelta, ChanPoint},
		"unable to parse fee_rate")
}

func TestUpdateChannelPolicy_BadTimeLockDelta(t *testing.T) {
	TestCommandTextInValidationError(t, runUpdateChannelPolicy,
		[]string{BaseFeeMsat, FeeRate, "BadTimeLockDelta", ChanPoint},
		"unable to parse time_lock_delta")
}

func TestUpdateChannelPolicy_BadTimeLockDeltaFlag(t *testing.T) {
	TestCommandTextInResponse(t, runUpdateChannelPolicy,
		[]string{"--time_lock_delta", "BadTimeLockDelta", BaseFeeMsat, FeeRate, ChanPoint},
		"updatechanpolicy - Update the channel policy for all channels, or a single channel")
}

func TestUpdateChannelPolicy_NotEnoughChanPointSegments(t *testing.T) {
	TestCommandValidationError(t, runUpdateChannelPolicy,
		[]string{BaseFeeMsat, FeeRate, TimeLockDelta, "BadChanPoint"},
		ErrBadChanPointFormat)
}

func TestUpdateChannelPolicy_TooManyChanPointSegments(t *testing.T) {
	TestCommandValidationError(t, runUpdateChannelPolicy,
		[]string{BaseFeeMsat, FeeRate, TimeLockDelta, "BadChanPoint:BadChanPoint:BadChanPoint"},
		ErrBadChanPointFormat)
}

func TestUpdateChannelPolicy_BadChanPointIndex(t *testing.T) {
	TestCommandTextInValidationError(t, runUpdateChannelPolicy,
		[]string{BaseFeeMsat, FeeRate, TimeLockDelta, "Txid:BadChanPointIndex"},
		"unable to decode output index:")
}

func TestUpdateChannelPolicy_RPCError(t *testing.T) {
	TestCommandRPCError(t, runUpdateChannelPolicy,
		[]string{"1", "2", "3", ChanPoint},
		io.ErrClosedPipe,
		io.ErrClosedPipe)
}

func runUpdateChannelPolicy(
	client lnrpc.LightningClient, args []string) (string, error) {

	return RunCommand(
		client, updateChannelPolicyCommand, updateChannelPolicy, "updatechanpolicy", args)
}

func expectedPolicyUpdateRequest() *lnrpc.PolicyUpdateRequest {

	channelPoint := lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{FundingTxidString},
		OutputIndex: 78}

	return &lnrpc.PolicyUpdateRequest{
		Scope:         &lnrpc.PolicyUpdateRequest_ChanPoint{ChanPoint: &channelPoint},
		BaseFeeMsat:   BaseFeeMsatInt,
		FeeRate:       FeeRateFloat,
		TimeLockDelta: TimeLockDeltaInt}
}
