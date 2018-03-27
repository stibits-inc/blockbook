package zec

import (
	"blockbook/bchain"
	"encoding/hex"
	"reflect"
	"testing"
)

var testTx1 = bchain.Tx{
	Hex:       "02000000019c012650c99d0ef761e863dbb966babf2cb7a7a2b5d90b1461c09521c473d23d000000006b483045022100f220f48c5267ef92a1e7a4d3b44fe9d97cce76eeba2785d45a0e2620b70e8d7302205640bc39e197ce19d95a98a3239af0f208ca289c067f80c97d8e411e61da5dee0121021721e83315fb5282f1d9d2a11892322df589bccd9cef45517b5fb3cfd3055c83ffffffff018eec1a3c040000001976a9149bb8229741305d8316ba3ca6a8d20740ce33c24188ac000000000162b4fc6b0000000000000000000000006ffa88c89b74f0f82e24744296845a0d0113b132ff5dfc2af34e6418eb15206af53078c4dd475cf143cd9a427983f5993622464b53e3a37d2519a946492c3977e30f0866550b9097222993a439a39260ac5e7d36aef38c7fdd1df3035a2d5817a9c20526e38f52f822d4db9d2f0156c4119d786d6e3a060ca871df7fae9a5c3a9c921b38ddc6414b13d16aa807389c68016e54bd6a9eb3b23a6bc7bf152e6dba15e9ec36f95dab15ad8f4a92a9d0309bbd930ef24bb7247bf534065c1e2f5b42e2c80eb59f48b4da6ec522319e065f8c4e463f95cc7fcad8d7ee91608e3c0ffcaa44129ba2d2da45d9a413919eca41af29faaf806a3eeb823e5a6c51afb1ec709505d812c0306bd76061a0a62d207355ad44d1ffce2b9e1dfd0818f79bd0f8e4031116b71fee2488484f17818b80532865773166cd389929e8409bb94e3948bd2e0215ef96d4e29d094590fda0de50715c11ff47c03380bb1d31b14e5b4ad8a372ca0b03364ef85f086b8a8eb5c56c3b1aee33e2cfbf1b2be1a3fb41b14b2c432b5d04d54c058fa87a96ae1d65d61b79360d09acc1e25a883fd7ae9a2a734a03362903021401c243173e1050b5cdb459b9ffc07c95e920f026618952d3a800b2e47e03b902084aed7ee8466a65d34abdbbd292781564dcd9b7440029d48c2640ebc196d4b40217f2872c1d0c1c9c2abf1147d6a5a9501895bc92960bfa182ceeb76a658224f1022bc53c4c1cd6888d72a152dc1aec5ba8a1d750fb7e498bee844d3481e4b4cd210227f94f775744185c9f24571b7df0c1c694cb2d3e4e9b955ed0b1caad2b02b5702139c4fbba03f0e422b2f3e4fc822b4f58baf32e7cd217cdbdec8540cb13d6496f271959b72a05e130eeffbe5b9a7fcd2793347cd9c0ea695265669844c363190f690c52a600cf413c3f00bdc5e9d1539e0cc63f4ec2945e0d86e6304a6deb5651e73eac21add5a641dfc95ab56200ed40d81f76755aee4659334c17ed3841ca5a5ab22f923956be1d264be2b485a0de55404510ece5c73d6626798be688f9dc18b69846acfe897a357cc4afe31f57fea32896717f124290e68f36f849fa6ecf76e02087f8c19dbc566135d7fa2daca2d843b9cc5bc3897d35f1de7d174f6407658f4a3706c12cea53d880b4d8c4d45b3f0d210214f815be49a664021a4a44b4a63e06a41d76b46f9aa6bad248e8d1a974ae7bbae5ea8ac269447db91637a19346729083cad5aebd5ff43ea13d04783068e9136da321b1152c666d2995d0ca06b26541deac62f4ef91f0e4af445b18a5c2a17c96eada0b27f85bb26dfb8f16515114c6b9f88037e2b85b3b84b65822eb99c992d99d12dcf9c71e5b46a586016faf5758483a716566db95b42187c101df68ca0554824e1c23cf0302bea03ad0a146af57e91794a268b8c82d78211718c8b5fea286f5de72fc7dfffecddcc02413525c472cb26022641d4bec2b8b7e71a7beb9ee18b82632799498eeee9a351cb9431a8d1906d5164acdf351bd538c3e9d1da8a211fe1cd18c44e72d8cdf16ce3fc9551552c05d52846ea7ef619232102588395cc2bcce509a4e7f150262a76c15475496c923dfce6bfc05871467ee7c213b39ea365c010083e0b1ba8926d3a9e586d8b11c9bab2a47d888bc7cb1a226c0086a1530e295d0047547006f4c8f1c24cdd8e16bb3845749895dec95f03fcda97d3224f6875b1b7b1c819d2fd35dd30968a3c82bc480d10082caf9d9dda8f9ec649c136c7fa07978099d97eaf4abfdc9854c266979d3cfc868f60689b6e3098b6c52a21796fe7c259d9a0dadf1b6efa59297d4c8c902febe7acf826eed30d40d2ac5119be91b51f4839d94599872c9a93c3e2691294914034001d3a278cb4a84d4ae048c0201a97e4cf1341ee663a162f5b586355018b9e5e30624ccdbeacf7d0382afacaf45f08e84d30c50bcd4e55c3138377261deb4e8c2931cd3c51cee94a048ae4839517b6e6537a5c0148d3830a33fea719ef9b4fa437e4d5fecdb646397c19ee56a0973c362a81803895cdc67246352dc566689cb203f9ebda900a5537bbb75aa25ddf3d4ab87b88737a58d760e1d271f08265daae1fe056e71971a8b826e5b215a05b71f99315b167dd2ec78874189657acafac2b5eeb9a901913f55f7ab69e1f9b203504448d414e71098b932a2309db57257eb3fef9de2f2a5a69aa46747d7b827df838345d38b95772bdab8c178c45777b92e8773864964b8e12ae29dbc1b21bf6527589f6bec71ff1cbb9928477409811c2e8150c79c3f21027ee954863b716875d3e9adfc6fdb18cd57a49bb395ca5c42da56f3beb78aad3a7a487de34a870bca61f3cdec422061328c83c910ab32ea7403c354915b7ebee29e1fea5a75158197e4a68e103f017fd7de5a70148ee7ce59356b1a74f83492e14faaa6cd4870bcc004e6eb0114d3429b74ea98fe2851b4553467a7660074e69b040aa31220d0e405d9166dbaf15e3ae2d8ec3b049ed99d17e0743bb6a1a7c3890bbdb7117f7374ad7a59aa1ab47d10445b28f4bc033794a71f88a8bf024189e9d27f9dc5859a4296437585b215656f807aca9dad35747494a43b8a1cf38be2b18a13de32a262ab29f9ba271c4fbce1a470a8243ebf9e7fd37b09262314afbb9a7e1802",
	Blocktime: 1521645728,
	Txid:      "e64aac0c211ad210c90934f06b1cc932327329e41a9f70c6eb76f79ef798b7b8",
	LockTime:  0,
	Vin: []bchain.Vin{
		{
			ScriptSig: bchain.ScriptSig{
				Hex: "483045022100f220f48c5267ef92a1e7a4d3b44fe9d97cce76eeba2785d45a0e2620b70e8d7302205640bc39e197ce19d95a98a3239af0f208ca289c067f80c97d8e411e61da5dee0121021721e83315fb5282f1d9d2a11892322df589bccd9cef45517b5fb3cfd3055c83",
			},
			Txid:     "3dd273c42195c061140bd9b5a2a7b72cbfba66b9db63e861f70e9dc95026019c",
			Vout:     0,
			Sequence: 4294967295,
		},
	},
	Vout: []bchain.Vout{
		{
			Value: 181.88266638,
			N:     0,
			ScriptPubKey: bchain.ScriptPubKey{
				Hex: "76a9149bb8229741305d8316ba3ca6a8d20740ce33c24188ac",
				Addresses: []string{
					"t1Y4yL14ACHaAbjemkdpW7nYNHWnv1yQbDA",
				},
			},
		},
	},
}

var testTxPacked1 = "000475b06aff8103010102547801ff820001080103486578010c00010454786964010c0001084c6f636b54696d65010600010356696e01ff88000104566f757401ff9000010d436f6e6669726d6174696f6e73010600010454696d650104000109426c6f636b74696d6501040000001bff870201010c5b5d62636861696e2e56696e01ff880001ff8400004cff830301010356696e01ff840001050108436f696e62617365010c00010454786964010c000104566f7574010600010953637269707453696701ff8600010853657175656e636501060000001fff850301010953637269707453696701ff860001010103486578010c0000001cff8f0201010d5b5d62636861696e2e566f757401ff900001ff8a000034ff8903010104566f757401ff8a000103010556616c756501080001014e010600010c5363726970745075624b657901ff8c00000042ff8b0301010c5363726970745075624b657901ff8c000104010341736d010c000103486578010c00010454797065010c00010941646472657373657301ff8e00000016ff8d020101085b5d737472696e6701ff8e00010c0000fe1234ff8201fe105630323030303030303031396330313236353063393964306566373631653836336462623936366261626632636237613761326235643930623134363163303935323163343733643233643030303030303030366234383330343530323231303066323230663438633532363765663932613165376134643362343466653964393763636537366565626132373835643435613065323632306237306538643733303232303536343062633339653139376365313964393561393861333233396166306632303863613238396330363766383063393764386534313165363164613564656530313231303231373231653833333135666235323832663164396432613131383932333232646635383962636364396365663435353137623566623363666433303535633833666666666666666630313865656331613363303430303030303031393736613931343962623832323937343133303564383331366261336361366138643230373430636533336332343138386163303030303030303030313632623466633662303030303030303030303030303030303030303030303030366666613838633839623734663066383265323437343432393638343561306430313133623133326666356466633261663334653634313865623135323036616635333037386334646434373563663134336364396134323739383366353939333632323436346235336533613337643235313961393436343932633339373765333066303836363535306239303937323232393933613433396133393236306163356537643336616566333863376664643164663330333561326435383137613963323035323665333866353266383232643464623964326630313536633431313964373836643665336130363063613837316466376661653961356333613963393231623338646463363431346231336431366161383037333839633638303136653534626436613965623362323361366263376266313532653664626131356539656333366639356461623135616438663461393261396430333039626264393330656632346262373234376266353334303635633165326635623432653263383065623539663438623464613665633532323331396530363566386334653436336639356363376663616438643765653931363038653363306666636161343431323962613264326461343564396134313339313965636134316166323966616166383036613365656238323365356136633531616662316563373039353035643831326330333036626437363036316130613632643230373335356164343464316666636532623965316466643038313866373962643066386534303331313136623731666565323438383438346631373831386238303533323836353737333136366364333839393239653834303962623934653339343862643265303231356566393664346532396430393435393066646130646535303731356331316666343763303333383062623164333162313465356234616438613337326361306230333336346566383566303836623861386562356335366333623161656533336532636662663162326265316133666234316231346232633433326235643034643534633035386661383761393661653164363564363162373933363064303961636331653235613838336664376165396132613733346130333336323930333032313430316332343331373365313035306235636462343539623966666330376339356539323066303236363138393532643361383030623265343765303362393032303834616564376565383436366136356433346162646262643239323738313536346463643962373434303032396434386332363430656263313936643462343032313766323837326331643063316339633261626631313437643661356139353031383935626339323936306266613138326365656237366136353832323466313032326263353363346331636436383838643732613135326463316165633562613861316437353066623765343938626565383434643334383165346234636432313032323766393466373735373434313835633966323435373162376466306331633639346362326433653465396239353565643062316361616432623032623537303231333963346662626130336630653432326232663365346663383232623466353862616633326537636432313763646264656338353430636231336436343936663237313935396237326130356531333065656666626535623961376663643237393333343763643963306561363935323635363639383434633336333139306636393063353261363030636634313363336630306264633565396431353339653063633633663465633239343565306438366536333034613664656235363531653733656163323161646435613634316466633935616235363230306564343064383166373637353561656534363539333334633137656433383431636135613561623232663932333935366265316432363462653262343835613064653535343034353130656365356337336436363236373938626536383866396463313862363938343661636665383937613335376363346166653331663537666561333238393637313766313234323930653638663336663834396661366563663736653032303837663863313964626335363631333564376661326461636132643834336239636335626333383937643335663164653764313734663634303736353866346133373036633132636561353364383830623464386334643435623366306432313032313466383135626534396136363430323161346134346234613633653036613431643736623436663961613662616432343865386431613937346165376262616535656138616332363934343764623931363337613139333436373239303833636164356165626435666634336561313364303437383330363865393133366461333231623131353263363636643239393564306361303662323635343164656163363266346566393166306534616634343562313861356332613137633936656164613062323766383562623236646662386631363531353131346336623966383830333765326238356233623834623635383232656239396339393264393964313264636639633731653562343661353836303136666166353735383438336137313635363664623935623432313837633130316466363863613035353438323465316332336366303330326265613033616430613134366166353765393137393461323638623863383264373832313137313863386235666561323836663564653732666337646666666563646463633032343133353235633437326362323630323236343164346265633262386237653731613762656239656531386238323633323739393439386565656539613335316362393433316138643139303664353136346163646633353162643533386333653964316461386132313166653163643138633434653732643863646631366365336663393535313535326330356435323834366561376566363139323332313032353838333935636332626363653530396134653766313530323632613736633135343735343936633932336466636536626663303538373134363765653763323133623339656133363563303130303833653062316261383932366433613965353836643862313163396261623261343764383838626337636231613232366330303836613135333065323935643030343735343730303666346338663163323463646438653136626233383435373439383935646563393566303366636461393764333232346636383735623162376231633831396432666433356464333039363861336338326263343830643130303832636166396439646461386639656336343963313336633766613037393738303939643937656166346162666463393835346332363639373964336366633836386636303638396236653330393862366335326132313739366665376332353964396130646164663162366566613539323937643463386339303266656265376163663832366565643330643430643261633531313962653931623531663438333964393435393938373263396139336333653236393132393439313430333430303164336132373863623461383464346165303438633032303161393765346366313334316565363633613136326635623538363335353031386239653565333036323463636462656163663764303338326166616361663435663038653834643330633530626364346535356333313338333737323631646562346538633239333163643363353163656539346130343861653438333935313762366536353337613563303134386433383330613333666561373139656639623466613433376534643566656364623634363339376331396565353661303937336333363261383138303338393563646336373234363335326463353636363839636232303366396562646139303061353533376262623735616132356464663364346162383762383837333761353864373630653164323731663038323635646161653166653035366537313937316138623832366535623231356130356237316639393331356231363764643265633738383734313839363537616361666163326235656562396139303139313366353566376162363965316639623230333530343434386434313465373130393862393332613233303964623537323537656233666566396465326632613561363961613436373437643762383237646638333833343564333862393537373262646162386331373863343537373762393265383737333836343936346238653132616532396462633162323162663635323735383966366265633731666631636262393932383437373430393831316332653831353063373963336632313032376565393534383633623731363837356433653961646663366664623138636435376134396262333935636135633432646135366633626562373861616433613761343837646533346138373062636136316633636465633432323036313332386338336339313061623332656137343033633335343931356237656265653239653166656135613735313538313937653461363865313033663031376664376465356137303134386565376365353933353662316137346638333439326531346661616136636434383730626363303034653665623031313464333432396237346561393866653238353162343535333436376137363630303734653639623034306161333132323064306534303564393136366462616631356533616532643865633362303439656439396431376530373433626236613161376333383930626264623731313766373337346164376135396161316162343764313034343562323866346263303333373934613731663838613862663032343138396539643237663964633538353961343239363433373538356232313536353666383037616361396461643335373437343934613433623861316366333862653262313861313364653332613236326162323966396261323731633466626365316134373061383234336562663965376664333762303932363233313461666262396137653138303201406536346161633063323131616432313063393039333466303662316363393332333237333239653431613966373063366562373666373965663739386237623802010240336464323733633432313935633036313134306264396235613261376237326362666261363662396462363365383631663730653964633935303236303139630201ffd6343833303435303232313030663232306634386335323637656639326131653761346433623434666539643937636365373665656261323738356434356130653236323062373065386437333032323035363430626333396531393763653139643935613938613332333961663066323038636132383963303637663830633937643865343131653631646135646565303132313032313732316538333331356662353238326631643964326131313839323332326466353839626363643963656634353531376235666233636664333035356338330001fcffffffff00010101f81e6c90cd3ebc6640020232373661393134396262383232393734313330356438333136626133636136613864323037343063653333633234313838616302012374315934794c31344143486141626a656d6b647057376e594e48576e76317951624441000003fcb564f14000"

var testTx2 = bchain.Tx{
	Hex:       "01000000019cafb5c287980e6e5afb47339f6c1c81136d8255f5bd5226b36b01288494c46f000000006b483045022100c92b2f3c54918fa26288530c63a58197ea4974e5b6d92db792dd9717e6d9183c02204e577254213675466a6adad3ae6e9384cf8269fb2dd9943b86fac0c0ad8e3f98012102c99dab469e63b232488b3e7acb9cfcab7e5755f61aad318d9e06b38e5ea22880feffffff0223a7a784010000001976a914826f87806ddd4643730be99b41c98acc379e83db88ac80969800000000001976a914e395634b7684289285926d4c64db395b783720ec88ac6e750400",
	Blocktime: 1521637604,
	Txid:      "bb47a9dd926de63e9d4f8dac58c3f63f4a079569ed3b80e932274a80f60e58b5",
	LockTime:  292206,
	Vin: []bchain.Vin{
		{
			ScriptSig: bchain.ScriptSig{
				Hex: "483045022100c92b2f3c54918fa26288530c63a58197ea4974e5b6d92db792dd9717e6d9183c02204e577254213675466a6adad3ae6e9384cf8269fb2dd9943b86fac0c0ad8e3f98012102c99dab469e63b232488b3e7acb9cfcab7e5755f61aad318d9e06b38e5ea22880",
			},
			Txid:     "6fc4948428016bb32652bdf555826d13811c6c9f3347fb5a6e0e9887c2b5af9c",
			Vout:     0,
			Sequence: 4294967294,
		},
	},
	Vout: []bchain.Vout{
		{
			Value: 65.20547107,
			N:     0,
			ScriptPubKey: bchain.ScriptPubKey{
				Hex: "76a914826f87806ddd4643730be99b41c98acc379e83db88ac",
				Addresses: []string{
					"t1VmHTTwpEtwvojxodN2CSQqLYi1hzY3cAq",
				},
			},
		},
		{
			Value: .1,
			N:     1,
			ScriptPubKey: bchain.ScriptPubKey{
				Hex: "76a914e395634b7684289285926d4c64db395b783720ec88ac",
				Addresses: []string{
					"t1ecxMXpphUTRQXGLXnVhJ6ucqD3DZipddg",
				},
			},
		},
	},
}

var testTxPacked2 = "000475796aff8103010102547801ff820001080103486578010c00010454786964010c0001084c6f636b54696d65010600010356696e01ff88000104566f757401ff9000010d436f6e6669726d6174696f6e73010600010454696d650104000109426c6f636b74696d6501040000001bff870201010c5b5d62636861696e2e56696e01ff880001ff8400004cff830301010356696e01ff840001050108436f696e62617365010c00010454786964010c000104566f7574010600010953637269707453696701ff8600010853657175656e636501060000001fff850301010953637269707453696701ff860001010103486578010c0000001cff8f0201010d5b5d62636861696e2e566f757401ff900001ff8a000034ff8903010104566f757401ff8a000103010556616c756501080001014e010600010c5363726970745075624b657901ff8c00000042ff8b0301010c5363726970745075624b657901ff8c000104010341736d010c000103486578010c00010454797065010c00010941646472657373657301ff8e00000016ff8d020101085b5d737472696e6701ff8e00010c0000fe0410ff8201fe01c4303130303030303030313963616662356332383739383065366535616662343733333966366331633831313336643832353566356264353232366233366230313238383439346334366630303030303030303662343833303435303232313030633932623266336335343931386661323632383835333063363361353831393765613439373465356236643932646237393264643937313765366439313833633032323034653537373235343231333637353436366136616461643361653665393338346366383236396662326464393934336238366661633063306164386533663938303132313032633939646162343639653633623233323438386233653761636239636663616237653537353566363161616433313864396530366233386535656132323838306665666666666666303232336137613738343031303030303030313937366139313438323666383738303664646434363433373330626539396234316339386163633337396538336462383861633830393639383030303030303030303031393736613931346533393536333462373638343238393238353932366434633634646233393562373833373230656338386163366537353034303001406262343761396464393236646536336539643466386461633538633366363366346130373935363965643362383065393332323734613830663630653538623501fd04756e01010240366663343934383432383031366262333236353262646635353538323664313338313163366339663333343766623561366530653938383763326235616639630201ffd6343833303435303232313030633932623266336335343931386661323632383835333063363361353831393765613439373465356236643932646237393264643937313765366439313833633032323034653537373235343231333637353436366136616461643361653665393338346366383236396662326464393934336238366661633063306164386533663938303132313032633939646162343639653633623233323438386233653761636239636663616237653537353566363161616433313864396530366233386535656132323838300001fcfffffffe00010201f8257b2170264d504002023237366139313438323666383738303664646434363433373330626539396234316339386163633337396538336462383861630201237431566d4854547770457477766f6a786f644e32435351714c596931687a5933634171000001f89a9999999999b93f0101010232373661393134653339353633346237363834323839323835393236643463363464623339356237383337323065633838616302012374316563784d587070685554525158474c586e56684a367563714433445a6970646467000003fcb564b1c800"

// FIXME gob has variable output so the test was disabled, fix when there will be implemented new protobuf marshalling
func TestPackTx(t *testing.T) {
	t.Skip("skipping TestPackTx")

	type args struct {
		tx        bchain.Tx
		height    uint32
		blockTime int64
		parser    *ZCashBlockParser
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "zec-1",
			args: args{
				tx:        testTx1,
				height:    292272,
				blockTime: 1521645728,
				parser:    &ZCashBlockParser{},
			},
			want:    testTxPacked1,
			wantErr: false,
		},
		{
			name: "zec-2",
			args: args{
				tx:        testTx2,
				height:    292217,
				blockTime: 1521637604,
				parser:    &ZCashBlockParser{},
			},
			want:    testTxPacked2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.parser.PackTx(&tt.args.tx, tt.args.height, tt.args.blockTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("packTx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			h := hex.EncodeToString(got)
			if !reflect.DeepEqual(h, tt.want) {
				t.Errorf("packTx() = %v, want %v", h, tt.want)
			}
		})
	}
}

func TestUnpackTx(t *testing.T) {
	type args struct {
		packedTx string
		parser   *ZCashBlockParser
	}
	tests := []struct {
		name    string
		args    args
		want    *bchain.Tx
		want1   uint32
		wantErr bool
	}{
		{
			name: "zec-1",
			args: args{
				packedTx: testTxPacked1,
				parser:   &ZCashBlockParser{},
			},
			want:    &testTx1,
			want1:   292272,
			wantErr: false,
		},
		{
			name: "zec-2",
			args: args{
				packedTx: testTxPacked2,
				parser:   &ZCashBlockParser{},
			},
			want:    &testTx2,
			want1:   292217,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := hex.DecodeString(tt.args.packedTx)
			got, got1, err := tt.args.parser.UnpackTx(b)
			if (err != nil) != tt.wantErr {
				t.Errorf("unpackTx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unpackTx() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("unpackTx() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
