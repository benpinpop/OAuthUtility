local OAuthUtil = require("OAuthUtility")

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

testHeaders()
testHexConversion()
testPercentEncoding()