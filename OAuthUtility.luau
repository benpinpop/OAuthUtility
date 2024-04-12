--[[
MIT License

Copyright (c) 2024 Ben Polonsky

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

--!strict

local OAuthUtil = {
	--CONFIGURATION
	nonceLength = 15, --Recommended: 11-15. Messing with this is not recommended unless you know what you're doing.

	--Don't touch this
	usedNonces = {},
}

local HttpService = game:GetService("HttpService")

export type headerInformation = {
	consumerKey: string, 
	token: string, 
	consumerSecret: string?, 
	tokenSecret: string?, 
	callbackUrl: string?,
	signatureMethod: "PLAINTEXT" | "HMAC-SHA1" | "HMAC-SHA256" | "HMAC-SHA512",
	requestType: "OPTIONS" | "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "TRACE" | "CONNECT" | "PATCH", 
	requestUrl: string,
	overrideNonce: string?,
	overrideTimestamp: number?,
}


local HashLib = require("sha2")
local base64 = require("base64")

OAuthUtil.signatureEncoding = {
	["PLAINTEXT"] = function(consumerSecret, tokenSecret)
		if tokenSecret then
			return OAuthUtil.encodeString(consumerSecret) .. "&" .. OAuthUtil.encodeString(tokenSecret)
		else
			return OAuthUtil.encodeString(consumerSecret) .. "&"
		end
	end,

	--key is consumerSecret and tokenSecret
	["HMAC-SHA1"] = function(consumerSecret: string, tokenSecret: string, signatureBaseString: string)
		local key = OAuthUtil.signatureEncoding.PLAINTEXT(consumerSecret,tokenSecret)
		return HashLib.hmac(HashLib.sha1, key, signatureBaseString)
	end,
	["HMAC-SHA256"] = function(consumerSecret, tokenSecret, signatureBaseString)
		local key = OAuthUtil.signatureEncoding.PLAINTEXT(consumerSecret,tokenSecret)
		return HashLib.hmac(HashLib.sha256, key, signatureBaseString) 
	end,
	["HMAC-SHA512"] = function(consumerSecret, tokenSecret, signatureBaseString)
		local key = OAuthUtil.signatureEncoding.PLAINTEXT(consumerSecret,tokenSecret)
		return HashLib.hmac(HashLib.sha512, key, signatureBaseString) 
	end
}

-- UTILITY FUNCTIONS --
function OAuthUtil.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
	
function OAuthUtil.encodeString(strToEncode: string): string
	local encodedStr = string.gsub(strToEncode, "[^%w%-%._~']", function(char)
		return `%{string.format("%X", string.byte(char))}`
	end)
	return encodedStr
end

function OAuthUtil.generateNonce(): string
	local nonce = HttpService:GenerateGUID(false)

	if table.find(OAuthUtil.usedNonces,nonce) then
		return OAuthUtil.generateNonce()
	else
		table.insert(OAuthUtil.usedNonces,nonce)
		return nonce
	end
end

function OAuthUtil.encodeHeader(array: {}): nil
	for index, value in pairs(array) do
		array[index] = OAuthUtil.encodeString(value) 
	end
end

function OAuthUtil.generateSignature(signatureType: string, consumerSecret: string, tokenSecret: string, signatureBaseString: string): string
	return OAuthUtil.signatureEncoding[signatureType](consumerSecret,tokenSecret, signatureBaseString)
end

function OAuthUtil.sortParameters(array: {})
	local sortOrder = {}

	for index,value in pairs(array) do
		table.insert(sortOrder,index)
	end

	table.sort(sortOrder)

	return sortOrder
end

function OAuthUtil.createBaseParameterString(sortOrder, OAuthHeader)
	local baseString: string = ""
	
	for index,headerIndex in pairs(sortOrder) do
		if not OAuthHeader[headerIndex] then warn(`{headerIndex} not found with OAuthHeader!`) continue end

		baseString ..= headerIndex .. "=" .. OAuthHeader[headerIndex]

		if index ~= #sortOrder then
			baseString ..= "&"
		end
	end

	return baseString
end

function OAuthUtil.generateHeader(parameters: headerInformation): string
	local OAuthHeader = {
		["oauth_signature_method"] = parameters.signatureMethod,
		["oauth_version"] = "1.0",
		["oauth_consumer_key"] = parameters.consumerKey, 
		["oauth_token"] = parameters.token,
		["oauth_callback"] = parameters.callbackUrl,
		["oauth_nonce"] = parameters.overrideNonce or OAuthUtil.generateNonce(),
		["oauth_timestamp"] = parameters.overrideTimestamp or os.time(),
	}

	OAuthUtil.encodeHeader(OAuthHeader)
	local sortOrder = OAuthUtil.sortParameters(OAuthHeader)

	local baseParameterString = OAuthUtil.createBaseParameterString(sortOrder, OAuthHeader)

	local methodUrlString = `{OAuthUtil.encodeString(parameters.requestType)}&{OAuthUtil.encodeString(parameters.requestUrl)}`
	baseParameterString = OAuthUtil.encodeString(baseParameterString)

	local signatureBaseString = methodUrlString .. "&"  .. baseParameterString

	local oauth_signature = OAuthUtil.generateSignature(parameters.signatureMethod,parameters.consumerSecret,parameters.tokenSecret, signatureBaseString)

	if typeof(oauth_signature) == "string" then
		print(base64.encode(OAuthUtil.fromhex(oauth_signature)))
	end

	return baseParameterString
end

OAuthUtil.generateHeader({
	consumerKey = "clientIdentifier",
	token = "accessT!oken",
	consumerSecret = "clientSecret",
	tokenSecret = "tokenSecret",
	callbackUrl = nil,
	signatureMethod = "HMAC-SHA1",
	requestType = "GET",
	requestUrl = "https://www.google.com/",
	overrideNonce = "dskfm329sdam121",
	overrideTimestamp = 1424991993
})

return OAuthUtil
