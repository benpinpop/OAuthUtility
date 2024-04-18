local OAuthUtil = require("OAuthUtility")
local sha = require("sha2")

hexToString = OAuthUtil.convertHexToString

local function testHexConversion()
    assert(hexToString("41") == "A", "Test 1 failed")
    assert(hexToString("48656C6C6F20576F726C64") == "Hello World", "Test 2 failed")
    assert(hexToString("") == "", "Test 3 failed")
    assert(hexToString("4F6E65") == "One", "Test 4 failed")
    assert(hexToString("48656C6C6F2123") == "Hello!#", "Test 5 failed")

    print("Hex conversion tests passed.")
end

local function testPercentEncoding()
    assert(OAuthUtil.encodeString("abc123ABC") == "abc123ABC", "Test 1 failed")
    assert(OAuthUtil.encodeString("-") == "-", "Test 2 failed")
    assert(OAuthUtil.encodeString(".") == ".", "Test 3 failed")
    assert(OAuthUtil.encodeString("testPercent!@#") == "testPercent%21%40%23", "Test 4 failed")
    assert(OAuthUtil.encodeString("xEEEKEJn/0YZ}c}QR:x63)Rjt%Z8_V") == "xEEEKEJn%2F0YZ%7Dc%7DQR%3Ax63%29Rjt%25Z8_V", "Test 5 failed")
    assert(OAuthUtil.encodeString("%&H2YxSAj-nV?wmmD/gcA4pD}cVhnc") == "%25%26H2YxSAj-nV%3FwmmD%2FgcA4pD%7DcVhnc", "Test 6 failed")
    assert(OAuthUtil.encodeString("%&H2YxSAj-nV?wmmD/gcA4pD}cVhnc") == "%25%26H2YxSAj-nV%3FwmmD%2FgcA4pD%7DcVhnc", "Test 7 failed")

    print("Percent encoding tests passed.")
end

local function testHeaders()
    local t = os.clock()
    local test1 = OAuthUtil.new({
        consumerKey = "clientIdentifier",
        token = "accessT!oken",
        consumerSecret = "clientSecret",
        tokenSecret = "tokenSecret",
        callbackUrl = nil,
        signatureMethod = "HMAC-SHA1",
        requestType = "GET",
        requestUrl = "https://www.google.com/",
    })

    assert(test1:generateHeader("dskfm329sdam121",1424991993)=="OAuth oauth_consumer_key=clientIdentifier,oauth_nonce=dskfm329sdam121,oauth_signature=AbVSVNHFRFiTXaeRbGfB25hZRnE%3D,oauth_signature_method=HMAC-SHA1,oauth_timestamp=1424991993,oauth_token=accessT!oken,oauth_version=1.0", "Test 1: Failed")

    local test2 = OAuthUtil.new({
        consumerKey = "consumerKey",
        token = "accessToken",
        consumerSecret = "consumerSecret",
        tokenSecret = "tokenSecret",
        callbackUrl = nil,
        signatureMethod = "HMAC-SHA256",
        requestType = "GET",
        requestUrl = "https://www.google.com/",
    })

    assert(test2:generateHeader("FDRMnsTvyF1",1462028997)=="OAuth oauth_consumer_key=consumerKey,oauth_nonce=FDRMnsTvyF1,oauth_signature=08J2SOdsoIktspyvNDzJaJDvBpo43avWqgp7TR3hWDE%3D,oauth_signature_method=HMAC-SHA256,oauth_timestamp=1462028997,oauth_token=accessToken,oauth_version=1.0", "Test 2: Failed")

    test2:setRequestType("POST")
    assert(test2:generateHeader("FDRMnsTvyF1",1462028997)=="OAuth oauth_consumer_key=consumerKey,oauth_nonce=FDRMnsTvyF1,oauth_signature=zoPMAIXyfGKAV102oXCl7bps60u4f3d6Ek5H3kWqE54%3D,oauth_signature_method=HMAC-SHA256,oauth_timestamp=1462028997,oauth_token=accessToken,oauth_version=1.0", "Test 2: Failed")
    print("Header generation tests passed.")
end

-- Taken from: https://github.com/Egor-Skriptunoff/pure_lua_SHA/blob/master/sha2_test.lua
local function testHmac()

    local hmac = sha.hmac
 
    assert(hmac(sha.sha1,   "your key", "your message") == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
    assert(hmac(sha.sha512, "your key", "your message") == "2f5ddcdbd062a5392f07b0cd0262bf52c21bfb3db513296240cca8d5accc09d18d96be0a94995be4494c032f1eda946ad549fb61ccbe985d160f0b2f9588d34b")
    assert(hmac(sha.md5,    "", "") == "74e6f7298a9c2d168935f58c001bad88")
    assert(hmac(sha.sha256, "", "") == "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
    assert(hmac(sha.sha1,   "", "") == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
    assert(hmac(sha.md5,    "key", "The quick brown fox jumps over the lazy dog") == "80070713463e7749b90c2dc24911e275")
    assert(hmac(sha.sha256, "key", "The quick brown fox jumps over the lazy dog") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    assert(hmac(sha.sha1,   "key", "The quick brown fox jumps over the lazy dog") == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
 
    -- chunk-by-chunk mode
    local append = hmac(sha.sha1, "key")
    append("The quick brown fox")
    append("")  -- empty string is allowed as a valid chunk
    append(" jumps over the lazy dog")
    assert(append() == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")  -- invocation without an argument receives the result
 
    local key, message = ("\170"):rep(131), "Test Using Larger Than Block-Size Key - Hash Key First"
    assert(hmac(sha.sha3_224, key, message) == "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f")
    assert(hmac(sha.sha3_256, key, message) == "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b")
    assert(hmac(sha.sha3_384, key, message) == "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc")
    assert(hmac(sha.sha3_512, key, message) == "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4")
 
    assert(not pcall(hmac, function(x) return sha.sha256(x) end, "key", "message"))  -- must raise "unknown hash function" error

    print("Hashing tests passed.")
end

local function generateRandomString(length)
    local charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local randomString = ""
    local charsetLength = string.len(charset)

    for i = 1, length do
        local randomIndex = math.random(1, charsetLength)
        local randomChar = string.sub(charset, randomIndex, randomIndex)
        randomString = randomString .. randomChar
    end

    return randomString
end

local function benchmarkHeaderGeneration(signatureType: "HMAC-SHA1" | "HMAC-SHA256" | "HMAC-SHA512" | "PLAINTEXT")
    local iterations = 10000
    local startTime = os.clock()
 
     for i = 1, iterations do
         local test = OAuthUtil.new({
             consumerKey = generateRandomString(math.random(10,15)),
             token = generateRandomString(math.random(10,15)),
             consumerSecret = generateRandomString(math.random(10,15)),
             tokenSecret = generateRandomString(math.random(10,15)),
             callbackUrl = nil,
             signatureMethod = signatureType,
             requestType = "GET",
             requestUrl = "https://www.google.com/",
         })
 
        test:generateHeader(generateRandomString(math.random(10,15)), 1424991993)
     end
 
     local endTime = os.clock()
     local elapsedTime = endTime - startTime
     local averageTime = elapsedTime / iterations
 
     print("Benchmark results for: " .. signatureType)
     print("Iterations: " .. iterations)
     print("Total time: " .. elapsedTime .. " seconds")
     print("Average time per iteration: " .. averageTime .. " seconds")
 end

testHexConversion()
testPercentEncoding()
testHeaders()

local signatureTypes = {"HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA512", "PLAINTEXT"}

for i,v in pairs(signatureTypes) do
    benchmarkHeaderGeneration(v)
end 

