package bchain

import (
	"encoding/binary"
	"time"

	"github.com/golang/glog"
	zmq "github.com/pebbe/zmq4"
)

// MQ is message queue listener handle
type MQ struct {
	context   *zmq.Context
	socket    *zmq.Socket
	isRunning bool
	finished  chan bool
}

// NotificationType is type of notification
type NotificationType int

const (
	// NotificationUnknown is unknown
	NotificationUnknown NotificationType = iota
	// NotificationNewBlock message is sent when there is a new block to be imported
	NotificationNewBlock NotificationType = iota
	// NotificationNewTx message is sent when there is a new mempool transaction
	NotificationNewTx NotificationType = iota
)

// NewMQ creates new Bitcoind ZeroMQ listener
// callback function receives messages
func NewMQ(binding string, callback func(NotificationType)) (*MQ, error) {
	context, err := zmq.NewContext()
	if err != nil {
		return nil, err
	}
	socket, err := context.NewSocket(zmq.SUB)
	if err != nil {
		return nil, err
	}
	err = socket.SetSubscribe("hashblock")
	if err != nil {
		return nil, err
	}
	err = socket.SetSubscribe("hashtx")
	if err != nil {
		return nil, err
	}
	// for now do not use raw subscriptions - we would have to handle skipped/lost notifications from zeromq
	// on each notification we do sync or syncmempool respectively
	// socket.SetSubscribe("rawblock")
	// socket.SetSubscribe("rawtx")
	err = socket.Connect(binding)
	if err != nil {
		return nil, err
	}
	glog.Info("MQ listening to ", binding)
	mq := &MQ{context, socket, true, make(chan bool)}
	go mq.run(callback)
	return mq, nil
}

func (mq *MQ) run(callback func(NotificationType)) {
	defer func() {
		if r := recover(); r != nil {
			glog.Error("MQ loop recovered from ", r)
		}
		mq.isRunning = false
		glog.Info("MQ loop terminated")
		mq.finished <- true
	}()
	mq.isRunning = true
	for {
		msg, err := mq.socket.RecvMessageBytes(0)
		if err != nil {
			if zmq.AsErrno(err) == zmq.Errno(zmq.ETERM) || err.Error() == "Socket is closed" {
				break
			}
			glog.Error("MQ RecvMessageBytes error ", err, ", ", zmq.AsErrno(err))
			time.Sleep(100 * time.Millisecond)
		}
		if msg != nil && len(msg) >= 3 {
			var nt NotificationType
			switch string(msg[0]) {
			case "hashblock":
				nt = NotificationNewBlock
				break
			case "hashtx":
				nt = NotificationNewTx
				break
			default:
				nt = NotificationUnknown
			}
			if glog.V(2) {
				sequence := uint32(0)
				if len(msg[len(msg)-1]) == 4 {
					sequence = binary.LittleEndian.Uint32(msg[len(msg)-1])
				}
				glog.Infof("MQ: %v %s-%d", nt, string(msg[0]), sequence)
			}
			callback(nt)
		}
	}
}

// Shutdown stops listening to the ZeroMQ and closes the connection
func (mq *MQ) Shutdown() error {
	glog.Info("MQ server shutdown")
	if mq.isRunning {
		mq.socket.SetUnsubscribe("hashtx")
		mq.socket.SetUnsubscribe("hashblock")
		// if errors in socket.Close or context.Term, let it close ungracefully
		if err := mq.socket.Close(); err != nil {
			return err
		}
		if err := mq.context.Term(); err != nil {
			return err
		}
		<-mq.finished
		glog.Info("MQ server shutdown finished")
	}
	return nil
}
