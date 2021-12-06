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

// GetAddrDescFromVout returns internal address representation (descriptor) of given transaction output
func (p *RavencoinParser) GetAddrDescFromVout(output *bchain.Vout) (bchain.AddressDescriptor, error) {
        ad, err := hex.DecodeString(output.ScriptPubKey.Hex)
        if err != nil {
                return ad, err
        }

        l := len(ad)
        if l > 25 {
                if ad[0] == 0x76 &&  ad[1] == 0xa9 && ad[2] == 0x14 && ad[l-1] == 0x75{
                        add := ad[0 : 25]
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
                if addrDesc[0] == 0x76 &&  addrDesc[1] == 0xa9 && addrDesc[2] == 0x14 && addrDesc[l-1] == 0x75 {
                	addressDesc = addrDesc[0:25]
                }
        }

        return p.BitcoinParser.GetAddressesFromAddrDesc(addressDesc)
}

// PackTx packs transaction to byte array using protobuf
func (p *RavencoinParser) PackTx(tx *bchain.Tx, height uint32, blockTime int64) ([]byte, error) {
	return p.baseparser.PackTx(tx, height, blockTime)
}

// UnpackTx unpacks transaction from protobuf byte array
func (p *RavencoinParser) UnpackTx(buf []byte) (*bchain.Tx, uint32, error) {
	return p.baseparser.UnpackTx(buf)
}
