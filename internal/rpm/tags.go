package rpm

// The tags read here, as rpm's lib/rpmtag.h numbers them. The signature header
// numbers its own tags from the same space, so some share a number with a tag
// of the header.

// Tags of the signature header.
const (
	sigDSA         = 267 // OpenPGP signature over the header, a key that is not RSA
	sigRSA         = 268 // OpenPGP signature over the header, an RSA key
	sigSHA1        = 269 // hex SHA-1 of the header
	sigLongSize    = 270 // header and payload size, int64
	sigLongPayload = 271 // payload size uncompressed, int64
	sigSHA256      = 273 // hex SHA-256 of the header
	sigOpenPGP     = 278 // the OpenPGP signatures of rpm 6, any number of them
	sigSize        = 1000
	sigPGP         = 1002 // OpenPGP signature over header and payload, RSA
	sigMD5         = 1004 // MD5 of header and payload
	sigGPG         = 1005 // OpenPGP signature over header and payload, not RSA
	sigPayloadSize = 1007
)

// Tags of the header.
const (
	tagName              = 1000
	tagVersion           = 1001
	tagRelease           = 1002
	tagEpoch             = 1003
	tagSummary           = 1004
	tagDescription       = 1005
	tagBuildTime         = 1006
	tagBuildHost         = 1007
	tagSize              = 1009
	tagVendor            = 1011
	tagLicense           = 1014
	tagPackager          = 1015
	tagGroup             = 1016
	tagURL               = 1020
	tagArch              = 1022
	tagOldFilenames      = 1027
	tagFileModes         = 1030
	tagFileFlags         = 1037
	tagSourceRPM         = 1044
	tagArchiveSize       = 1046
	tagProvideName       = 1047
	tagRequireFlags      = 1048
	tagRequireName       = 1049
	tagRequireVersion    = 1050
	tagConflictFlags     = 1053
	tagConflictName      = 1054
	tagConflictVersion   = 1055
	tagChangelogTime     = 1080
	tagChangelogName     = 1081
	tagChangelogText     = 1082
	tagObsoleteName      = 1090
	tagSourcePackage     = 1106
	tagProvideFlags      = 1112
	tagProvideVersion    = 1113
	tagObsoleteFlags     = 1114
	tagObsoleteVersion   = 1115
	tagDirIndexes        = 1116
	tagBaseNames         = 1117
	tagDirNames          = 1118
	tagLongSize          = 5009
	tagRecommendName     = 5046
	tagRecommendVersion  = 5047
	tagRecommendFlags    = 5048
	tagSuggestName       = 5049
	tagSuggestVersion    = 5050
	tagSuggestFlags      = 5051
	tagSupplementName    = 5052
	tagSupplementVersion = 5053
	tagSupplementFlags   = 5054
	tagEnhanceName       = 5055
	tagEnhanceVersion    = 5056
	tagEnhanceFlags      = 5057
	tagPayloadDigest     = 5092
	tagPayloadDigestAlgo = 5093
)

// The flags of a dependency.
const (
	senseLess       = 1 << 1
	senseGreater    = 1 << 2
	senseEqual      = 1 << 3
	sensePostTrans  = 1 << 5
	sensePreReq     = 1 << 6
	sensePreTrans   = 1 << 7
	senseScriptPre  = 1 << 9
	senseScriptPost = 1 << 10
	senseRPMLib     = 1 << 24
)

// fileGhost marks a file the package owns but does not carry.
const fileGhost = 1 << 6

// The digest algorithms of tagPayloadDigestAlgo, as OpenPGP numbers them.
const (
	hashMD5    = 1
	hashSHA1   = 2
	hashSHA256 = 8
	hashSHA384 = 9
	hashSHA512 = 10
	hashSHA224 = 11
)
