package sync

import (
	"blockbook/bchain"
	"blockbook/common"
	"blockbook/db"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var testMap = map[string]func(t *testing.T, th *TestHandler){
	"ConnectBlocks":         testConnectBlocks,
	"ConnectBlocksParallel": testConnectBlocksParallel,
	// "HandleFork":            testHandleFork,
}

type TestHandler struct {
	Coin     string
	Chain    bchain.BlockChain
	TestData *TestData
}

type Range struct {
	Lower uint32 `json:"lower"`
	Upper uint32 `json:"upper"`
}

type TestData struct {
	ConnectBlocks struct {
		SyncRanges []Range              `json:"syncRanges"`
		Blocks     map[uint32]BlockInfo `json:"blocks"`
	} `json:"connectBlocks"`
	HandleFork struct {
		SyncRanges []Range            `json:"syncRanges"`
		FakeBlocks map[uint32]BlockID `json:"fakeBlocks"`
		RealBlocks map[uint32]BlockID `json:"realBlocks"`
	} `json:"handleFork"`
}

type BlockID struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
}

type BlockInfo struct {
	BlockID
	NoTxs     uint32       `json:"noTxs"`
	TxDetails []*bchain.Tx `json:"txDetails"`
}

func IntegrationTest(t *testing.T, coin string, chain bchain.BlockChain, testConfig json.RawMessage) {
	tests, err := getTests(testConfig)
	if err != nil {
		t.Fatalf("Failed loading of test list: %s", err)
	}

	parser := chain.GetChainParser()
	td, err := loadTestData(coin, parser)
	if err != nil {
		t.Fatalf("Failed loading of test data: %s", err)
	}

	for _, test := range tests {
		if f, found := testMap[test]; found {
			h := TestHandler{Coin: coin, Chain: chain, TestData: td}
			t.Run(test, func(t *testing.T) { f(t, &h) })
		} else {
			t.Errorf("%s: test not found", test)
			continue
		}
	}
}

func getTests(cfg json.RawMessage) ([]string, error) {
	var v []string
	err := json.Unmarshal(cfg, &v)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, errors.New("No tests declared")
	}
	return v, nil
}

func loadTestData(coin string, parser bchain.BlockChainParser) (*TestData, error) {
	path := filepath.Join("sync/testdata", coin+".json")
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v TestData
	err = json.Unmarshal(b, &v)
	if err != nil {
		return nil, err
	}

	for _, b := range v.ConnectBlocks.Blocks {
		for _, tx := range b.TxDetails {
			// convert amounts in test json to bit.Int and clear the temporary JsonValue
			for i := range tx.Vout {
				vout := &tx.Vout[i]
				vout.ValueSat, err = parser.AmountToBigInt(vout.JsonValue)
				if err != nil {
					return nil, err
				}
				vout.JsonValue = ""
			}

			// get addresses parsed
			err := setTxAddresses(parser, tx)
			if err != nil {
				return nil, err
			}
		}
	}

	return &v, nil
}

func setTxAddresses(parser bchain.BlockChainParser, tx *bchain.Tx) error {
	// pack and unpack transaction in order to get addresses decoded - ugly but works
	var tmp *bchain.Tx
	b, err := parser.PackTx(tx, 0, 0)
	if err == nil {
		tmp, _, err = parser.UnpackTx(b)
		if err == nil {
			for i := 0; i < len(tx.Vout); i++ {
				tx.Vout[i].ScriptPubKey.Addresses = tmp.Vout[i].ScriptPubKey.Addresses
			}
		}
	}
	return err
}

func makeRocksDB(parser bchain.BlockChainParser, m *common.Metrics, is *common.InternalState) (*db.RocksDB, func(), error) {
	p, err := ioutil.TempDir("", "sync_test")
	if err != nil {
		return nil, nil, err
	}

	d, err := db.NewRocksDB(p, 1<<17, 1<<14, parser, m)
	if err != nil {
		return nil, nil, err
	}

	d.SetInternalState(is)

	closer := func() {
		d.Close()
		os.RemoveAll(p)
	}

	return d, closer, nil
}

var metricsRegistry = map[string]*common.Metrics{}

func getMetrics(name string) (*common.Metrics, error) {
	if m, found := metricsRegistry[name]; found {
		return m, nil
	} else {
		m, err := common.GetMetrics(name)
		if err != nil {
			return nil, err
		}
		metricsRegistry[name] = m
		return m, nil
	}
}

func withRocksDBAndSyncWorker(t *testing.T, h *TestHandler, startHeight uint32, fn func(*db.RocksDB, *db.SyncWorker, chan os.Signal)) {
	m, err := getMetrics(h.Coin)
	if err != nil {
		t.Fatal(err)
	}
	is := &common.InternalState{}

	d, closer, err := makeRocksDB(h.Chain.GetChainParser(), m, is)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	ch := make(chan os.Signal)

	sw, err := db.NewSyncWorker(d, h.Chain, 8, 0, int(startHeight), false, ch, m, is)
	if err != nil {
		t.Fatal(err)
	}

	fn(d, sw, ch)
}

func testConnectBlocks(t *testing.T, h *TestHandler) {
	for _, rng := range h.TestData.ConnectBlocks.SyncRanges {
		withRocksDBAndSyncWorker(t, h, rng.Lower, func(d *db.RocksDB, sw *db.SyncWorker, ch chan os.Signal) {
			upperHash, err := h.Chain.GetBlockHash(rng.Upper)
			if err != nil {
				t.Fatal(err)
			}

			err = db.ConnectBlocks(sw, func(hash string, height uint32) {
				if hash == upperHash {
					close(ch)
				}
			}, true)
			if err != nil {
				if err.Error() != fmt.Sprintf("connectBlocks interrupted at height %d", rng.Upper) {
					t.Fatal(err)
				}
			}

			height, hash, err := d.GetBestBlock()
			if err != nil {
				t.Fatal(err)
			}
			if height != rng.Upper {
				t.Fatalf("Upper block height mismatch: %d != %d", height, rng.Upper)
			}
			if hash != upperHash {
				t.Fatalf("Upper block hash mismatch: %s != %s", hash, upperHash)
			}

			t.Run("verifyBlockInfo", func(t *testing.T) { verifyBlockInfo(t, d, h, rng) })
			t.Run("verifyTransactions", func(t *testing.T) { verifyTransactions(t, d, h, rng) })
			t.Run("verifyAddresses", func(t *testing.T) { verifyAddresses(t, d, h, rng) })
		})
	}
}

func testConnectBlocksParallel(t *testing.T, h *TestHandler) {
	for _, rng := range h.TestData.ConnectBlocks.SyncRanges {
		withRocksDBAndSyncWorker(t, h, rng.Lower, func(d *db.RocksDB, sw *db.SyncWorker, ch chan os.Signal) {
			upperHash, err := h.Chain.GetBlockHash(rng.Upper)
			if err != nil {
				t.Fatal(err)
			}

			err = sw.ConnectBlocksParallel(rng.Lower, rng.Upper)
			if err != nil {
				t.Fatal(err)
			}

			height, hash, err := d.GetBestBlock()
			if err != nil {
				t.Fatal(err)
			}
			if height != rng.Upper {
				t.Fatalf("Upper block height mismatch: %d != %d", height, rng.Upper)
			}
			if hash != upperHash {
				t.Fatalf("Upper block hash mismatch: %s != %s", hash, upperHash)
			}

			t.Run("verifyBlockInfo", func(t *testing.T) { verifyBlockInfo(t, d, h, rng) })
			t.Run("verifyTransactions", func(t *testing.T) { verifyTransactions(t, d, h, rng) })
			t.Run("verifyAddresses", func(t *testing.T) { verifyAddresses(t, d, h, rng) })
		})
	}
}

func verifyBlockInfo(t *testing.T, d *db.RocksDB, h *TestHandler, rng Range) {
	for height := rng.Lower; height <= rng.Upper; height++ {
		block, found := h.TestData.ConnectBlocks.Blocks[height]
		if !found {
			continue
		}

		bi, err := d.GetBlockInfo(height)
		if err != nil {
			t.Errorf("GetBlockInfo(%d) error: %s", height, err)
			continue
		}
		if bi == nil {
			t.Errorf("GetBlockInfo(%d) returned nil", height)
			continue
		}

		if bi.Hash != block.Hash {
			t.Errorf("Block hash mismatch: %s != %s", bi.Hash, block.Hash)
		}

		if bi.Txs != block.NoTxs {
			t.Errorf("Number of transactions in block %s mismatch: %d != %d", bi.Hash, bi.Txs, block.NoTxs)
		}
	}
}

func verifyTransactions(t *testing.T, d *db.RocksDB, h *TestHandler, rng Range) {
	type txInfo struct {
		txid     string
		vout     uint32
		isOutput bool
	}
	addr2txs := make(map[string][]txInfo)
	checkMap := make(map[string][]bool)

	for height := rng.Lower; height <= rng.Upper; height++ {
		block, found := h.TestData.ConnectBlocks.Blocks[height]
		if !found {
			continue
		}

		for _, tx := range block.TxDetails {
			for _, vin := range tx.Vin {
				for _, a := range vin.Addresses {
					addr2txs[a] = append(addr2txs[a], txInfo{tx.Txid, vin.Vout, false})
					checkMap[a] = append(checkMap[a], false)
				}
			}
			for _, vout := range tx.Vout {
				for _, a := range vout.ScriptPubKey.Addresses {
					addr2txs[a] = append(addr2txs[a], txInfo{tx.Txid, vout.N, true})
					checkMap[a] = append(checkMap[a], false)
				}
			}
		}
	}

	for addr, txs := range addr2txs {
		err := d.GetTransactions(addr, rng.Lower, rng.Upper, func(txid string, vout uint32, isOutput bool) error {
			for i, tx := range txs {
				if txid == tx.txid && vout == tx.vout && isOutput == tx.isOutput {
					checkMap[addr][i] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	for addr, txs := range addr2txs {
		for i, tx := range txs {
			if !checkMap[addr][i] {
				t.Errorf("%s: transaction not found %+v", addr, tx)
			}
		}
	}
}

func verifyAddresses(t *testing.T, d *db.RocksDB, h *TestHandler, rng Range) {
	parser := h.Chain.GetChainParser()

	for height := rng.Lower; height <= rng.Upper; height++ {
		block, found := h.TestData.ConnectBlocks.Blocks[height]
		if !found {
			continue
		}

		for _, tx := range block.TxDetails {
			ta, err := d.GetTxAddresses(tx.Txid)
			if err != nil {
				t.Fatal(err)
			}

			txInfo := getTxInfo(tx)
			taInfo, err := getTaInfo(parser, ta)
			if err != nil {
				t.Fatal(err)
			}

			if ta.Height != height {
				t.Errorf("Tx %s: block height mismatch: %d != %d", tx.Txid, ta.Height, height)
				continue
			}

			if len(txInfo.inputs) > 0 && !reflect.DeepEqual(taInfo.inputs, txInfo.inputs) {
				t.Errorf("Tx %s: inputs mismatch: got %q, want %q", tx.Txid, taInfo.inputs, txInfo.inputs)
			}

			if !reflect.DeepEqual(taInfo.outputs, txInfo.outputs) {
				t.Errorf("Tx %s: outputs mismatch: got %q, want %q", tx.Txid, taInfo.outputs, txInfo.outputs)
			}

			if taInfo.valOutSat.Cmp(&txInfo.valOutSat) != 0 {
				t.Errorf("Tx %s: total output amount mismatch: got %s, want %s",
					tx.Txid, taInfo.valOutSat.String(), txInfo.valOutSat.String())
			}

			if len(txInfo.inputs) > 0 {
				treshold := "0.0001"
				fee := new(big.Int).Sub(&taInfo.valInSat, &taInfo.valOutSat)
				if strings.Compare(parser.AmountToDecimalString(fee), treshold) > 0 {
					t.Errorf("Tx %s: suspicious amounts: input ∑ [%s] - output ∑ [%s] > %s",
						tx.Txid, taInfo.valInSat.String(), taInfo.valOutSat.String(), treshold)
				}
			}
		}
	}
}

type txInfo struct {
	inputs    []string
	outputs   []string
	valInSat  big.Int
	valOutSat big.Int
}

func getTxInfo(tx *bchain.Tx) *txInfo {
	info := &txInfo{inputs: []string{}, outputs: []string{}}

	for _, vin := range tx.Vin {
		for _, a := range vin.Addresses {
			info.inputs = append(info.inputs, a)
		}
	}
	for _, vout := range tx.Vout {
		for _, a := range vout.ScriptPubKey.Addresses {
			info.outputs = append(info.outputs, a)
		}
		info.valOutSat.Add(&info.valOutSat, &vout.ValueSat)
	}

	return info
}

func getTaInfo(parser bchain.BlockChainParser, ta *db.TxAddresses) (*txInfo, error) {
	info := &txInfo{inputs: []string{}, outputs: []string{}}

	for i := range ta.Inputs {
		info.valInSat.Add(&info.valInSat, &ta.Inputs[i].ValueSat)
		addrs, _, err := ta.Inputs[i].Addresses(parser)
		if err != nil {
			return nil, err
		}
		info.inputs = append(info.inputs, addrs...)
	}

	for i := range ta.Outputs {
		info.valOutSat.Add(&info.valOutSat, &ta.Outputs[i].ValueSat)
		addrs, _, err := ta.Outputs[i].Addresses(parser)
		if err != nil {
			return nil, err
		}
		info.outputs = append(info.outputs, addrs...)
	}

	return info, nil
}
