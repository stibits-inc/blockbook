package server

import (
	"blockbook/api"
	"blockbook/bchain"
	"blockbook/common"
	"blockbook/db"
	"encoding/json"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	"github.com/juju/errors"
)

const upgradeFailed = "Upgrade failed: "
const outChannelSize = 500
const defaultTimeout = 60 * time.Second

var (
	// ErrorMethodNotAllowed is returned when client tries to upgrade method other than GET
	ErrorMethodNotAllowed = errors.New("Method not allowed")

	connectionCounter uint64
)

type websocketReq struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type websocketRes struct {
	ID   string      `json:"id"`
	Data interface{} `json:"data"`
}

type websocketChannel struct {
	id            uint64
	conn          *websocket.Conn
	out           chan *websocketRes
	ip            string
	requestHeader http.Header
	alive         bool
	aliveLock     sync.Mutex
}

// WebsocketServer is a handle to websocket server
type WebsocketServer struct {
	socket                    *websocket.Conn
	upgrader                  *websocket.Upgrader
	db                        *db.RocksDB
	txCache                   *db.TxCache
	chain                     bchain.BlockChain
	chainParser               bchain.BlockChainParser
	metrics                   *common.Metrics
	is                        *common.InternalState
	api                       *api.Worker
	newBlockSubscriptions     map[*websocketChannel]string
	newBlockSubscriptionsLock sync.Mutex
	addressSubscriptions      map[string]map[*websocketChannel]string
	addressSubscriptionsLock  sync.Mutex
}

// NewWebsocketServer creates new websocket interface to blockbook and returns its handle
func NewWebsocketServer(db *db.RocksDB, chain bchain.BlockChain, txCache *db.TxCache, metrics *common.Metrics, is *common.InternalState) (*WebsocketServer, error) {
	api, err := api.NewWorker(db, chain, txCache, is)
	if err != nil {
		return nil, err
	}
	s := &WebsocketServer{
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024 * 32,
			WriteBufferSize: 1024 * 32,
		},
		db:                    db,
		txCache:               txCache,
		chain:                 chain,
		chainParser:           chain.GetChainParser(),
		metrics:               metrics,
		is:                    is,
		api:                   api,
		newBlockSubscriptions: make(map[*websocketChannel]string),
		addressSubscriptions:  make(map[string]map[*websocketChannel]string),
	}
	return s, nil
}

// ServeHTTP sets up handler of websocket channel
func (s *WebsocketServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, upgradeFailed+ErrorMethodNotAllowed.Error(), 503)
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, upgradeFailed+err.Error(), 503)
		return
	}
	c := &websocketChannel{
		id:            atomic.AddUint64(&connectionCounter, 1),
		conn:          conn,
		out:           make(chan *websocketRes, outChannelSize),
		ip:            r.RemoteAddr,
		requestHeader: r.Header,
		alive:         true,
	}
	go s.inputLoop(c)
	go s.outputLoop(c)
	s.onConnect(c)
}

// GetHandler returns http handler
func (s *WebsocketServer) GetHandler() http.Handler {
	return s
}

func (s *WebsocketServer) closeChannel(c *websocketChannel) {
	c.aliveLock.Lock()
	defer c.aliveLock.Unlock()
	if c.alive {
		c.conn.Close()
		c.alive = false
		//clean out
		close(c.out)
		for len(c.out) > 0 {
			<-c.out
		}
		s.onDisconnect(c)
	}
}

func (c *websocketChannel) IsAlive() bool {
	c.aliveLock.Lock()
	defer c.aliveLock.Unlock()
	return c.alive
}

func (s *WebsocketServer) inputLoop(c *websocketChannel) {
	defer func() {
		if r := recover(); r != nil {
			glog.Error("recovered from panic: ", r, ", ", c.id)
			debug.PrintStack()
			s.closeChannel(c)
		}
	}()
	for {
		t, d, err := c.conn.ReadMessage()
		if err != nil {
			s.closeChannel(c)
			return
		}
		switch t {
		case websocket.TextMessage:
			var req websocketReq
			err := json.Unmarshal(d, &req)
			if err != nil {
				glog.Error("Error parsing message from ", c.id, ", ", string(d), ", ", err)
				s.closeChannel(c)
				return
			}
			go s.onRequest(c, &req)
		case websocket.BinaryMessage:
			glog.Error("Binary message received from ", c.id, ", ", c.ip)
			s.closeChannel(c)
			return
		case websocket.PingMessage:
			c.conn.WriteControl(websocket.PongMessage, nil, time.Now().Add(defaultTimeout))
			break
		case websocket.CloseMessage:
			s.closeChannel(c)
			return
		case websocket.PongMessage:
			// do nothing
		}
	}
}

func (s *WebsocketServer) outputLoop(c *websocketChannel) {
	for m := range c.out {
		err := c.conn.WriteJSON(m)
		if err != nil {
			glog.Error("Error sending message to ", c.id, ", ", err)
			s.closeChannel(c)
		}
	}
}

func (s *WebsocketServer) onConnect(c *websocketChannel) {
	glog.Info("Client connected ", c.id, ", ", c.ip)
	s.metrics.WebsocketClients.Inc()
}

func (s *WebsocketServer) onDisconnect(c *websocketChannel) {
	s.unsubscribeNewBlock(c)
	glog.Info("Client disconnected ", c.id, ", ", c.ip)
	s.metrics.WebsocketClients.Dec()
}

var requestHandlers = map[string]func(*WebsocketServer, *websocketChannel, *websocketReq) (interface{}, error){
	"getAccountInfo": func(s *WebsocketServer, c *websocketChannel, req *websocketReq) (rv interface{}, err error) {
		r, err := unmarshalGetAccountInfoRequest(req.Params)
		if err == nil {
			rv, err = s.getAccountInfo(r)
		}
		return
	},
	"sendTransaction": func(s *WebsocketServer, c *websocketChannel, req *websocketReq) (rv interface{}, err error) {
		r := struct {
			Hex string `json:"hex"`
		}{}
		err = json.Unmarshal(req.Params, &r)
		if err == nil {
			rv, err = s.sendTransaction(r.Hex)
		}
		return
	},
	"subscribeNewBlock": func(s *WebsocketServer, c *websocketChannel, req *websocketReq) (rv interface{}, err error) {
		rv, err = s.subscribeNewBlock(c, req)
		return
	},
	"unsubscribeNewBlock": func(s *WebsocketServer, c *websocketChannel, req *websocketReq) (rv interface{}, err error) {
		rv, err = s.unsubscribeNewBlock(c)
		return
	},
}

func (s *WebsocketServer) onRequest(c *websocketChannel, req *websocketReq) {
	var err error
	var data interface{}
	defer func() {
		if r := recover(); r != nil {
			glog.Error("Client ", c.id, ", onRequest ", req.Method, " recovered from panic: ", r)
			debug.PrintStack()
			e := resultError{}
			e.Error.Message = "Internal error"
			data = e
		}
		// nil data means no response
		if data != nil {
			c.out <- &websocketRes{
				ID:   req.ID,
				Data: data,
			}
		}
	}()
	t := time.Now()
	defer s.metrics.WebsocketReqDuration.With(common.Labels{"method": req.Method}).Observe(float64(time.Since(t)) / 1e3) // in microseconds
	f, ok := requestHandlers[req.Method]
	if ok {
		data, err = f(s, c, req)
	} else {
		err = errors.New("unknown method")
	}
	if err == nil {
		glog.V(1).Info("Client ", c.id, " onRequest ", req.Method, " success")
		s.metrics.SocketIORequests.With(common.Labels{"method": req.Method, "status": "success"}).Inc()
	} else {
		glog.Error("Client ", c.id, " onMessage ", req.Method, ": ", errors.ErrorStack(err))
		s.metrics.SocketIORequests.With(common.Labels{"method": req.Method, "status": err.Error()}).Inc()
		e := resultError{}
		e.Error.Message = err.Error()
		data = e
	}
}

type accountInfoReq struct {
	Descriptor string `json:"descriptor"`
	Details    string `json:"details"`
	PageSize   int    `json:"pageSize"`
	Page       int    `json:"page"`
}

func unmarshalGetAccountInfoRequest(params []byte) (*accountInfoReq, error) {
	var r accountInfoReq
	err := json.Unmarshal(params, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *WebsocketServer) getAccountInfo(req *accountInfoReq) (res *api.Address, err error) {
	if s.chainParser.GetChainType() == bchain.ChainEthereumType {
		var opt api.GetAddressOption
		switch req.Details {
		case "balance":
			opt = api.Balance
		case "txids":
			opt = api.TxidHistory
		case "txs":
			opt = api.TxHistory
		default:
			opt = api.Basic
		}
		return s.api.GetAddress(req.Descriptor, req.Page, req.PageSize, opt, api.AddressFilterNone)
	}
	return nil, errors.New("Not implemented")
}

func (s *WebsocketServer) sendTransaction(tx string) (res resultSendTransaction, err error) {
	txid, err := s.chain.SendRawTransaction(tx)
	if err != nil {
		return res, err
	}
	res.Result = txid
	return
}

func (s *WebsocketServer) subscribeNewBlock(c *websocketChannel, req *websocketReq) (res interface{}, err error) {
	s.newBlockSubscriptionsLock.Lock()
	defer s.newBlockSubscriptionsLock.Unlock()
	s.newBlockSubscriptions[c] = req.ID
	return
}

func (s *WebsocketServer) unsubscribeNewBlock(c *websocketChannel) (res interface{}, err error) {
	s.newBlockSubscriptionsLock.Lock()
	defer s.newBlockSubscriptionsLock.Unlock()
	delete(s.newBlockSubscriptions, c)
	return
}

// OnNewBlock is a callback that broadcasts info about new block to subscribed clients
func (s *WebsocketServer) OnNewBlock(hash string, height uint32) {
	s.newBlockSubscriptionsLock.Lock()
	defer s.newBlockSubscriptionsLock.Unlock()
	data := struct {
		Height uint32 `json:"height"`
		Hash   string `json:"hash"`
	}{
		Height: height,
		Hash:   hash,
	}
	for c, id := range s.newBlockSubscriptions {
		if c.IsAlive() {
			c.out <- &websocketRes{
				ID:   id,
				Data: &data,
			}
		}
	}
	glog.Info("broadcasting new block ", height, " ", hash, " to ", len(s.newBlockSubscriptions), " channels")
}
