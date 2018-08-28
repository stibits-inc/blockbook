package api

import (
	"blockbook/bchain"
	"blockbook/common"
	"blockbook/db"
	"fmt"
	"math/big"
	"time"

	"github.com/golang/glog"
	"github.com/juju/errors"
)

// Worker is handle to api worker
type Worker struct {
	db          *db.RocksDB
	txCache     *db.TxCache
	chain       bchain.BlockChain
	chainParser bchain.BlockChainParser
	is          *common.InternalState
}

// NewWorker creates new api worker
func NewWorker(db *db.RocksDB, chain bchain.BlockChain, txCache *db.TxCache, is *common.InternalState) (*Worker, error) {
	w := &Worker{
		db:          db,
		txCache:     txCache,
		chain:       chain,
		chainParser: chain.GetChainParser(),
		is:          is,
	}
	return w, nil
}

func (w *Worker) getAddressesFromVout(vout *bchain.Vout) ([]string, bool, error) {
	addrDesc, err := w.chainParser.GetAddrDescFromVout(vout)
	if err != nil {
		return nil, false, err
	}
	return w.chainParser.GetAddressesFromAddrDesc(addrDesc)
}

// GetTransaction reads transaction data from txid
func (w *Worker) GetTransaction(txid string, bestheight uint32, spendingTxs bool) (*Tx, error) {
	bchainTx, height, err := w.txCache.GetTransaction(txid, bestheight)
	if err != nil {
		return nil, NewApiError(fmt.Sprintf("Tx not found, %v", err), true)
	}
	var blockhash string
	if bchainTx.Confirmations > 0 {
		blockhash, err = w.db.GetBlockHash(height)
		if err != nil {
			return nil, errors.Annotatef(err, "GetBlockHash %v", height)
		}
	}
	var valInSat, valOutSat, feesSat big.Int
	vins := make([]Vin, len(bchainTx.Vin))
	for i := range bchainTx.Vin {
		bchainVin := &bchainTx.Vin[i]
		vin := &vins[i]
		vin.Txid = bchainVin.Txid
		vin.N = i
		vin.Vout = bchainVin.Vout
		vin.ScriptSig.Hex = bchainVin.ScriptSig.Hex
		//  bchainVin.Txid=="" is coinbase transaction
		if bchainVin.Txid != "" {
			// load spending addresses from TxAddresses
			ta, err := w.db.GetTxAddresses(bchainVin.Txid)
			if err != nil {
				return nil, errors.Annotatef(err, "GetTxAddresses %v", bchainVin.Txid)
			}
			if ta == nil {
				// mempool transactions are not in TxAddresses, all confirmed should be there, log a problem
				if bchainTx.Confirmations > 0 {
					glog.Warning("DB inconsistency:  tx ", bchainVin.Txid, ": not found in txAddresses")
				}
				// try to load from backend
				otx, _, err := w.txCache.GetTransaction(bchainVin.Txid, bestheight)
				if err != nil {
					return nil, errors.Annotatef(err, "txCache.GetTransaction %v", bchainVin.Txid)
				}
				if len(otx.Vout) > int(vin.Vout) {
					vout := &otx.Vout[vin.Vout]
					vin.ValueSat = vout.ValueSat
					vin.Addresses, vin.Searchable, err = w.getAddressesFromVout(vout)
					if err != nil {
						glog.Errorf("getAddressesFromVout error %v, vout %+v", err, vout)
					}
				}
			} else {
				if len(ta.Outputs) > int(vin.Vout) {
					output := &ta.Outputs[vin.Vout]
					vin.ValueSat = output.ValueSat
					vin.Value = w.chainParser.AmountToDecimalString(&vin.ValueSat)
					vin.Addresses, vin.Searchable, err = output.Addresses(w.chainParser)
					if err != nil {
						glog.Errorf("output.Addresses error %v, tx %v, output %v", err, bchainVin.Txid, i)
					}
				}
			}
			vin.Value = w.chainParser.AmountToDecimalString(&vin.ValueSat)
			valInSat.Add(&valInSat, &vin.ValueSat)
		}
	}
	vouts := make([]Vout, len(bchainTx.Vout))
	for i := range bchainTx.Vout {
		bchainVout := &bchainTx.Vout[i]
		vout := &vouts[i]
		vout.N = i
		vout.ValueSat = bchainVout.ValueSat
		vout.Value = w.chainParser.AmountToDecimalString(&bchainVout.ValueSat)
		valOutSat.Add(&valOutSat, &bchainVout.ValueSat)
		vout.ScriptPubKey.Hex = bchainVout.ScriptPubKey.Hex

		vout.ScriptPubKey.Addresses = bchainVout.ScriptPubKey.Addresses
		if spendingTxs {
			// TODO
		}
	}
	// for coinbase transactions valIn is 0
	feesSat.Sub(&valInSat, &valOutSat)
	if feesSat.Sign() == -1 {
		feesSat.SetUint64(0)
	}
	// for now do not return size, we would have to compute vsize of segwit transactions
	// size:=len(bchainTx.Hex) / 2
	r := &Tx{
		Blockhash:     blockhash,
		Blockheight:   int(height),
		Blocktime:     bchainTx.Blocktime,
		Confirmations: bchainTx.Confirmations,
		Fees:          w.chainParser.AmountToDecimalString(&feesSat),
		Locktime:      bchainTx.LockTime,
		WithSpends:    spendingTxs,
		Time:          bchainTx.Time,
		Txid:          bchainTx.Txid,
		ValueIn:       w.chainParser.AmountToDecimalString(&valInSat),
		ValueOut:      w.chainParser.AmountToDecimalString(&valOutSat),
		Version:       bchainTx.Version,
		Vin:           vins,
		Vout:          vouts,
	}
	return r, nil
}

func (w *Worker) getAddressTxids(address string, mempool bool) ([]string, error) {
	var err error
	txids := make([]string, 0)
	if !mempool {
		err = w.db.GetTransactions(address, 0, ^uint32(0), func(txid string, vout uint32, isOutput bool) error {
			txids = append(txids, txid)
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		m, err := w.chain.GetMempoolTransactions(address)
		if err != nil {
			return nil, err
		}
		txids = append(txids, m...)
	}
	return txids, nil
}

func (t *Tx) getAddrVoutValue(addr string) *big.Int {
	var val big.Int
	for _, vout := range t.Vout {
		for _, a := range vout.ScriptPubKey.Addresses {
			if a == addr {
				val.Add(&val, &vout.ValueSat)
			}
		}
	}
	return &val
}

func (t *Tx) getAddrVinValue(addr string) *big.Int {
	var val big.Int
	for _, vin := range t.Vin {
		for _, a := range vin.Addresses {
			if a == addr {
				val.Add(&val, &vin.ValueSat)
			}
		}
	}
	return &val
}

// UniqueTxidsInReverse reverts the order of transactions (so that newest are first) and removes duplicate transactions
func UniqueTxidsInReverse(txids []string) []string {
	i := len(txids)
	ut := make([]string, i)
	txidsMap := make(map[string]struct{})
	for _, txid := range txids {
		_, e := txidsMap[txid]
		if !e {
			i--
			ut[i] = txid
			txidsMap[txid] = struct{}{}
		}
	}
	return ut[i:]
}

func (w *Worker) txFromTxAddress(txid string, ta *db.TxAddresses, bi *db.BlockInfo, bestheight uint32) *Tx {
	var err error
	var valInSat, valOutSat, feesSat big.Int
	vins := make([]Vin, len(ta.Inputs))
	for i := range ta.Inputs {
		tai := &ta.Inputs[i]
		vin := &vins[i]
		vin.N = i
		vin.ValueSat = tai.ValueSat
		vin.Value = w.chainParser.AmountToDecimalString(&vin.ValueSat)
		valInSat.Add(&valInSat, &vin.ValueSat)
		vin.Addresses, vin.Searchable, err = tai.Addresses(w.chainParser)
		if err != nil {
			glog.Errorf("tai.Addresses error %v, tx %v, input %v", err, txid, i)
		}
	}
	vouts := make([]Vout, len(ta.Outputs))
	for i := range ta.Outputs {
		tao := &ta.Outputs[i]
		vout := &vouts[i]
		vout.N = i
		vout.ValueSat = tao.ValueSat
		vout.Value = w.chainParser.AmountToDecimalString(&vout.ValueSat)
		valOutSat.Add(&valOutSat, &vout.ValueSat)
		vout.ScriptPubKey.Addresses, vout.ScriptPubKey.Searchable, err = tao.Addresses(w.chainParser)
		if err != nil {
			glog.Errorf("tai.Addresses error %v, tx %v, output %v", err, txid, i)
		}
	}
	// for coinbase transactions valIn is 0
	feesSat.Sub(&valInSat, &valOutSat)
	if feesSat.Sign() == -1 {
		feesSat.SetUint64(0)
	}
	r := &Tx{
		Blockhash:     bi.Hash,
		Blockheight:   int(ta.Height),
		Blocktime:     bi.Time,
		Confirmations: bestheight - ta.Height + 1,
		Fees:          w.chainParser.AmountToDecimalString(&feesSat),
		Time:          bi.Time,
		Txid:          txid,
		ValueIn:       w.chainParser.AmountToDecimalString(&valInSat),
		ValueOut:      w.chainParser.AmountToDecimalString(&valOutSat),
		Vin:           vins,
		Vout:          vouts,
	}
	return r
}

// GetAddress computes address value and gets transactions for given address
func (w *Worker) GetAddress(address string, page int, txsOnPage int, onlyTxids bool) (*Address, error) {
	start := time.Now()
	if page < 0 {
		page = 0
	}
	ba, err := w.db.GetAddressBalance(address)
	if err != nil {
		return nil, NewApiError(fmt.Sprintf("Address not found, %v", err), true)
	}
	if ba == nil {
		return nil, NewApiError("Address not found", true)
	}
	txc, err := w.getAddressTxids(address, false)
	if err != nil {
		return nil, errors.Annotatef(err, "getAddressTxids %v false", address)
	}
	txc = UniqueTxidsInReverse(txc)
	var txm []string
	// mempool only on the first page
	if page == 0 {
		txm, err = w.getAddressTxids(address, true)
		if err != nil {
			return nil, errors.Annotatef(err, "getAddressTxids %v true", address)
		}
		txm = UniqueTxidsInReverse(txm)
	}
	bestheight, _, err := w.db.GetBestBlock()
	if err != nil {
		return nil, errors.Annotatef(err, "GetBestBlock")
	}
	// paging
	from := page * txsOnPage
	totalPages := len(txc) / txsOnPage
	if from >= len(txc) {
		page = totalPages - 1
		if page < 0 {
			page = 0
		}
	}
	from = page * txsOnPage
	to := (page + 1) * txsOnPage
	if to > len(txc) {
		to = len(txc)
	}
	txs := make([]*Tx, len(txm)+to-from)
	txi := 0
	// load mempool transactions
	var uBalSat big.Int
	for _, tx := range txm {
		tx, err := w.GetTransaction(tx, bestheight, false)
		// mempool transaction may fail
		if err != nil {
			glog.Error("GetTransaction in mempool ", tx, ": ", err)
		} else {
			uBalSat.Sub(tx.getAddrVoutValue(address), tx.getAddrVinValue(address))
			txs[txi] = tx
			txi++
		}
	}
	if len(txc) != int(ba.Txs) {
		glog.Warning("DB inconsistency for address ", address, ": number of txs from column addresses ", len(txc), ", from addressBalance ", ba.Txs)
	}
	for i := from; i < to; i++ {
		txid := txc[i]
		ta, err := w.db.GetTxAddresses(txid)
		if err != nil {
			return nil, errors.Annotatef(err, "GetTxAddresses %v", txid)
		}
		if ta == nil {
			glog.Warning("DB inconsistency:  tx ", txid, ": not found in txAddresses")
			continue
		}
		bi, err := w.db.GetBlockInfo(ta.Height)
		if err != nil {
			return nil, errors.Annotatef(err, "GetBlockInfo %v", ta.Height)
		}
		if bi == nil {
			glog.Warning("DB inconsistency:  block height ", ta.Height, ": not found in db")
			continue
		}
		txs[txi] = w.txFromTxAddress(txid, ta, bi, bestheight)
		txi++
	}
	r := &Address{
		AddrStr:                 address,
		Balance:                 w.chainParser.AmountToDecimalString(&ba.BalanceSat),
		TotalReceived:           w.chainParser.AmountToDecimalString(ba.ReceivedSat()),
		TotalSent:               w.chainParser.AmountToDecimalString(&ba.SentSat),
		TxApperances:            len(txc),
		UnconfirmedBalance:      w.chainParser.AmountToDecimalString(&uBalSat),
		UnconfirmedTxApperances: len(txm),
		Transactions:            txs[:txi],
		Page:                    page,
		TotalPages:              totalPages,
		TxsOnPage:               txsOnPage,
	}
	glog.Info(address, " finished in ", time.Since(start))
	return r, nil
}
