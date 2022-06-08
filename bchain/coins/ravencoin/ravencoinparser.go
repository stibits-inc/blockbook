package ravencoin

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/martinboehm/btcd/wire"
	"github.com/martinboehm/btcutil/chaincfg"
	"github.com/martinboehm/btcutil/txscript"
	"github.com/trezor/blockbook/bchain"
	"github.com/trezor/blockbook/bchain/coins/btc"
)

// magic numbers
const (
	MainnetMagic wire.BitcoinNet = 0x4e564152
	TestnetMagic wire.BitcoinNet = 0x544e5652
)

// chain parameters
var (
	MainNetParams chaincfg.Params
	TestNetParams chaincfg.Params
)

func init() {
	MainNetParams = chaincfg.MainNetParams
	MainNetParams.Net = MainnetMagic
	MainNetParams.PubKeyHashAddrID = []byte{60}
	MainNetParams.ScriptHashAddrID = []byte{122}

	TestNetParams = chaincfg.TestNet3Params
	TestNetParams.Net = TestnetMagic
	TestNetParams.PubKeyHashAddrID = []byte{111}
	TestNetParams.ScriptHashAddrID = []byte{196}
}

// RavencoinParser handle
type RavencoinParser struct {
	*btc.BitcoinLikeParser
	baseparser *bchain.BaseParser
}

// NewRavencoinParser returns new RavencoinParser instance
func NewRavencoinParser(params *chaincfg.Params, c *btc.Configuration) *RavencoinParser {
	return &RavencoinParser{
		BitcoinLikeParser: btc.NewBitcoinLikeParser(params, c),
		baseparser:        &bchain.BaseParser{},
	}
}

// GetChainParams contains network parameters
func GetChainParams(chain string) *chaincfg.Params {
	if !chaincfg.IsRegistered(&MainNetParams) {
		err := chaincfg.Register(&MainNetParams)
		if err == nil {
			err = chaincfg.Register(&TestNetParams)
		}
		if err != nil {
			panic(err)
		}
	}
	switch chain {
	case "test":
		return &TestNetParams
	default:
		return &MainNetParams
	}
}

func AssetNameScriptOffset(script []byte) int {
	nStartingIndex := 0
	scriptLen := len(script)
	if scriptLen > 31 {
		//OP_RVN_ASSET = 0xc0,  RVN_R = 114, RVN_V = 118, RVN_N = 110
		if script[25] == 0xc0 { // OP_RVN_ASSET is always in the 25 index of the script if it exists
			idx := -1

			if script[27] == 114 { // Check to see if RVN starts at 27 ( this->size() < 105)
				if script[28] == 118 {
					if script[29] == 110 {
						idx = 30
					}
				}

			} else {
				if script[28] == 114 { // Check to see if RVN starts at 28 ( this->size() >= 105)
					if script[29] == 118 {
						if script[30] == 110 {
							idx = 31
						}
					}
				}
			}

			if idx > 0 {
				nStartingIndex = idx + 1
			}
		}
	}

	return nStartingIndex
}

func NewAssetFromScriptPubKey(script []byte, nStartingIndex int) (string, uint64) {
	scriptLen := len(script)
	if script == nil || scriptLen == 0 || scriptLen > 0x100 { //MAX_SCRIPT_LENGTH = 0x100
		return "", 0
	}
	off := 0

	assetScriptLen := scriptLen - nStartingIndex
	assetScript := script[nStartingIndex : nStartingIndex+assetScriptLen]
	name_size := int(assetScript[off])
	off += 1
	var name string
	var amount uint64

	if off <= assetScriptLen {
		name = string(assetScript[off : off+name_size])
		off += name_size
	}
	if (off + binary.Size(amount)) <= assetScriptLen {
		amount = binary.LittleEndian.Uint64(assetScript[off : off+binary.Size(amount)])
	} else {
		amount = 0
	}

	if assetScript[assetScriptLen-1] != 0x75 { //OP_DROP = 0x75
		return "", 0
	}
	return name, amount
}

// GetAssetFromScriptPubKey returns asset for given address descriptor with flag if asset exist
func (p *RavencoinParser) GetAssetFromScriptPubKey(ad []byte) (bchain.Asset, bool) {
	var asset bchain.Asset
	var isAsset bool
	isAsset = false
	l := len(ad)
	if l > 25 {
		if ad[0] == 0x76 && ad[1] == 0xa9 && ad[2] == 0x14 && ad[l-1] == 0x75 {
			nStartingIndex := AssetNameScriptOffset(ad)
			assetName, assetAmount := NewAssetFromScriptPubKey(ad, nStartingIndex)
			asset = bchain.Asset{
				Name:   string(assetName),
				Amount: float64(assetAmount),
				//TODO MEHDI : Add IPFS & UNIT
			}
			isAsset = true
		}
	}

	return asset, isAsset
}

// GetAssetFromAddressDesc returns asset for given address descriptor with flag if asset exist
func (p *RavencoinParser) GetAssetFromAddressDesc(output *bchain.Vout) (bchain.Asset, bool) {
	ad, err := hex.DecodeString(output.ScriptPubKey.Hex)
	var asset bchain.Asset
	if err != nil {
		return asset, false
	}

	l := len(ad)
	if l > 25 {
		if ad[0] == 0x76 && ad[1] == 0xa9 && ad[2] == 0x14 && ad[l-1] == 0x75 {
			return p.GetAssetFromScriptPubKey(ad)
		}
	}

	return asset, false
}

// GetAddrDescFromVout returns internal address representation (descriptor) of given transaction output
func (p *RavencoinParser) GetAddrDescFromVout(output *bchain.Vout) (bchain.AddressDescriptor, error) {
	ad, err := hex.DecodeString(output.ScriptPubKey.Hex)
	if err != nil {
		return ad, err
	}

	l := len(ad)
	if l > 25 {
		if ad[0] == 0x76 && ad[1] == 0xa9 && ad[2] == 0x14 && ad[l-1] == 0x75 {
			add := ad[0:25]

			return add, err
		}
	}

	// convert possible P2PK script to P2PKH
	// so that all transactions by given public key are indexed together
	return txscript.ConvertP2PKtoP2PKH(p.Params.Base58CksumHasher, ad)
}

// GetAddressesFromAddrDesc returns addresses for given address descriptor (asset supported)  with flag if the addresses are searchable
func (p *RavencoinParser) GetAddressesFromAddrDesc(addrDesc bchain.AddressDescriptor) ([]string, bool, error) {
	var addressDesc bchain.AddressDescriptor
	addressDesc = addrDesc
	l := binary.Size(addrDesc)

	if l > 25 {
		if addrDesc[0] == 0x76 && addrDesc[1] == 0xa9 && addrDesc[2] == 0x14 && addrDesc[l-1] == 0x75 {
			addressDesc = addrDesc[0:25]
		}
	}

	return p.BitcoinLikeParser.GetAddressesFromAddrDesc(addressDesc)
}

// GetChainType is type of the blockchain, default is ChainBitcoinType
func (p *RavencoinParser) GetChainType() bchain.ChainType {
	return bchain.ChainRavencoinType
}

// PackTx packs transaction to byte array using protobuf
func (p *RavencoinParser) PackTx(tx *bchain.Tx, height uint32, blockTime int64) ([]byte, error) {
	return p.baseparser.PackTx(tx, height, blockTime)
}

// UnpackTx unpacks transaction from protobuf byte array
func (p *RavencoinParser) UnpackTx(buf []byte) (*bchain.Tx, uint32, error) {
	return p.baseparser.UnpackTx(buf)
}
