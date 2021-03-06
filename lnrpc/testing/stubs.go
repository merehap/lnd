package lnrpctesting

import (
	"time"

	"github.com/lightningnetwork/lnd/lnrpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type StubContext struct {
}

func (c *StubContext) Done() <-chan struct{} {
	return nil
}

func (c *StubContext) Err() error {
	return nil
}

func (c *StubContext) Deadline() (time.Time, bool) {
	return time.Unix(0, 0), true
}

func (c *StubContext) Value(key interface{}) interface{} {
	return nil
}

type StubStream struct {
}

func (s *StubStream) Context() context.Context {
	return new(StubContext)
}

func (s *StubStream) SendMsg(m interface{}) error {
	return nil
}

func (s *StubStream) RecvMsg(m interface{}) error {
	return nil
}

type StubClientStream struct {
	grpc.Stream
}

func NewStubClientStream() StubClientStream {
	return StubClientStream{new(StubStream)}
}

func (cs *StubClientStream) Header() (metadata.MD, error) {
	md := metadata.MD{
		"key1": []string{"value1"},
		"key2": []string{"value2"},
	}

	return md, nil
}

func (cs *StubClientStream) Trailer() metadata.MD {
	return metadata.MD{
		"tkey1": []string{"trailerValue1"},
		"tkey2": []string{"trailerValue2"},
	}

}

func (cs *StubClientStream) CloseSend() error {
	return nil
}

type StubLightningSubscribeTransactionsClient struct {
	grpc.ClientStream
}

func (x *StubLightningSubscribeTransactionsClient) Recv() (*lnrpc.Transaction, error) {
	return new(lnrpc.Transaction), nil
}

type StubLightningOpenChannelClient struct {
	grpc.ClientStream
}

func (client *StubLightningOpenChannelClient) Recv() (*lnrpc.OpenStatusUpdate, error) {
	return new(lnrpc.OpenStatusUpdate), nil
}

type TerminatingStubLightningOpenChannelClient struct {
	grpc.ClientStream
	updates          []lnrpc.OpenStatusUpdate
	terminatingError error
}

func (client *TerminatingStubLightningOpenChannelClient) Recv() (*lnrpc.OpenStatusUpdate, error) {
	if len(client.updates) < 1 {
		return nil, client.terminatingError
	}

	update := client.updates[0]
	client.updates = client.updates[1:]

	return &update, nil
}

type StubLightningCloseChannelClient struct {
	grpc.ClientStream
}

func (x *StubLightningCloseChannelClient) Recv() (*lnrpc.CloseStatusUpdate, error) {
	return new(lnrpc.CloseStatusUpdate), nil
}

type StubLightningSubscribeInvoicesClient struct {
	grpc.ClientStream
}

func (x *StubLightningSubscribeInvoicesClient) Recv() (*lnrpc.Invoice, error) {
	return new(lnrpc.Invoice), nil
}

type StubLightningSubscribeChannelGraphClient struct {
	grpc.ClientStream
}

func (x *StubLightningSubscribeChannelGraphClient) Recv() (*lnrpc.GraphTopologyUpdate, error) {
	return new(lnrpc.GraphTopologyUpdate), nil
}
