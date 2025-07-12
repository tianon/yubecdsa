package main

// every "slot" (9c, 9d, etc) has, by convention, a corresponding data "object", and this map provides a conversion between those conventional mappings
//
// see also https://ram.tianon.xyz/post/2025/07/10/yubi-whati.html
var slotObjectMap = map[uint8]uint32{
	// wget -qO- 'https://ram.tianon.xyz/json/piv-objects.json' | jq --raw-output '.[] | "\t0x\(.slot): 0x\(.tag), // \(.description)"'

	0x9A: 0x5FC105, // X.509 Certificate for PIV Authentication
	0x9E: 0x5FC101, // X.509 Certificate for Card Authentication
	0x9C: 0x5FC10A, // X.509 Certificate for Digital Signature
	0x9D: 0x5FC10B, // X.509 Certificate for Key Management
	0x82: 0x5FC10D, // Retired X.509 Certificate for Key Management 1
	0x83: 0x5FC10E, // Retired X.509 Certificate for Key Management 2
	0x84: 0x5FC10F, // Retired X.509 Certificate for Key Management 3
	0x85: 0x5FC110, // Retired X.509 Certificate for Key Management 4
	0x86: 0x5FC111, // Retired X.509 Certificate for Key Management 5
	0x87: 0x5FC112, // Retired X.509 Certificate for Key Management 6
	0x88: 0x5FC113, // Retired X.509 Certificate for Key Management 7
	0x89: 0x5FC114, // Retired X.509 Certificate for Key Management 8
	0x8A: 0x5FC115, // Retired X.509 Certificate for Key Management 9
	0x8B: 0x5FC116, // Retired X.509 Certificate for Key Management 10
	0x8C: 0x5FC117, // Retired X.509 Certificate for Key Management 11
	0x8D: 0x5FC118, // Retired X.509 Certificate for Key Management 12
	0x8E: 0x5FC119, // Retired X.509 Certificate for Key Management 13
	0x8F: 0x5FC11A, // Retired X.509 Certificate for Key Management 14
	0x90: 0x5FC11B, // Retired X.509 Certificate for Key Management 15
	0x91: 0x5FC11C, // Retired X.509 Certificate for Key Management 16
	0x92: 0x5FC11D, // Retired X.509 Certificate for Key Management 17
	0x93: 0x5FC11E, // Retired X.509 Certificate for Key Management 18
	0x94: 0x5FC11F, // Retired X.509 Certificate for Key Management 19
	0x95: 0x5FC120, // Retired X.509 Certificate for Key Management 20
}
