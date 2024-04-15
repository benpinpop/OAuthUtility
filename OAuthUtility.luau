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

export type headerInformation = {
	consumerKey: string, 
	consumerSecret: string?, 
	callbackUrl: string?,
	requestUrl: string,
	signatureMethod: "PLAINTEXT" | "HMAC-SHA1" | "HMAC-SHA256" | "HMAC-SHA512",
}

local OAuthUtil = {
	--CONFIGURATION
	nonceLength = 15, --Recommended: 11-15. Messing with this is not recommended unless you know what you're doing.

	--Don't touch this
	usedNonces = {},
}

OAuthUtil.__index = OAuthUtil

local HttpService = game and game:GetService("HttpService") or {GenerateGUID = function()
	local randomString = ""

	for i = 1, OAuthUtil.nonceLength do
		randomString ..= math.random(0,9) 
	end
end}

local HashLib = require("sha2")
local base64 = require("base64")

local function convertHexToString(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
	
local function encodeString(strToEncode: string): string
	local encodedStr = string.gsub(strToEncode, "[^%w%-%._~']", function(char)
		return `%{string.format("%X", string.byte(char))}`
	end)
	return encodedStr
end

local function encodeHeader(array: {}): nil
	for index, value in pairs(array) do
		array[index] = encodeString(value) 
	end

	return array
end

--SIGNATURES
OAuthUtil.signatureEncoding = {
	["PLAINTEXT"] = function(consumerSecret, tokenSecret)
		if tokenSecret then
			return encodeString(consumerSecret) .. "&" .. encodeString(tokenSecret)
		else
			return encodeString(consumerSecret) .. "&"
		end
	end,
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

local function generateSignature(signatureType: string, consumerSecret: string, tokenSecret: string, signatureBaseString: string): string
	return OAuthUtil.signatureEncoding[signatureType](consumerSecret,tokenSecret, signatureBaseString)
end

local function sortParameters(array: {})
	local sortOrder = {}

	for index,value in pairs(array) do
		table.insert(sortOrder,index)
	end

	table.sort(sortOrder)

	return sortOrder
end

-- UTILITY FUNCTIONS --
function OAuthUtil.generateNonce(_retries: number): string
	if _retries > 15 then error(`Nonce (Random String) generation reached max of: {_retries} retries.`) end

	local nonce = HttpService:GenerateGUID(false)

	if table.find(OAuthUtil.usedNonces,nonce) then
		if not _retries then _retries = 0 end

		return OAuthUtil.generateNonce(_retries+1)
	else
		table.insert(OAuthUtil.usedNonces,nonce)
		return nonce
	end
end

function OAuthUtil.createSignatureBaseString(sortOrder, OAuthHeader, useAmpersand: boolean)
	local baseString: string = ""
	
	for index,headerIndex in pairs(sortOrder) do
		if not OAuthHeader[headerIndex] then warn(`{headerIndex} not found with OAuthHeader!`) continue end

		baseString ..= headerIndex .. "=" .. OAuthHeader[headerIndex]

		if index ~= #sortOrder then
			baseString ..= useAmpersand and "&" or ","
		end
	end

	return baseString
end

--Generate a signature
--Generate the actual header

function OAuthUtil.new(parameters: headerInformation)
	if not parameters.consumerSecret then error("Request failed: Cannot generate header without consumerSecret") end

	local requestInformation = {
		["parameters"] = {
			["oauth_signature_method"] = parameters.signatureMethod,
			["oauth_version"] = "1.0",
			["oauth_consumer_key"] = parameters.consumerKey, 
			["oauth_callback"] = parameters.callbackUrl,
			["oauth_token"] = parameters.token
		},
		["oauth_token_secret"] = parameters.tokenSecret,
		["oauth_consumer_secret"] = parameters.consumerSecret,
		["requestUrl"] = parameters.requestUrl -- example https://api.schoology.com/
	}

	setmetatable(requestInformation, OAuthUtil)

	return requestInformation
end

function OAuthUtil:setRequestUrl(requestUrl: string): nil
	self["requestUrl"] = requestUrl
end

function OAuthUtil:setTokenSecret(tokenSecret: string): nil
	self["oauth_token_secret"] = tokenSecret
end

function OAuthUtil:setToken(token: string): nil
	self["oauth_token"] = token
end

function OAuthUtil:createSignature(newRequestInformation: string,requestType): string
	local encodedParameters = encodeHeader(table.clone(newRequestInformation))
	local sortOrder = sortParameters(encodedParameters)

	local methodUrlString = `{encodeString(requestType)}&{encodeString(self.requestUrl)}`
	local baseParameterString = OAuthUtil.createSignatureBaseString(sortOrder, encodedParameters,true)

	baseParameterString = encodeString(baseParameterString)

	local signatureBaseString = methodUrlString .. "&"  .. baseParameterString
	local oauth_signature = generateSignature(self.parameters.oauth_signature_method,self.oauth_consumer_secret,self.oauth_token_secret, signatureBaseString)
	oauth_signature = encodeString(base64.encode(convertHexToString(oauth_signature)))

	return oauth_signature
end

function OAuthUtil:generateHeader(overrideNonce: string, overrideTimestamp: number, requestType: string): string
	local newRequestInformation = table.clone(self.parameters)
	
	newRequestInformation["oauth_nonce"] = overrideNonce or OAuthUtil.generateNonce()
	newRequestInformation["oauth_timestamp"] = overrideTimestamp or os.time()
	newRequestInformation["oauth_signature"]  = self:createSignature(newRequestInformation,requestType)

	local sortOrder = sortParameters(newRequestInformation)
	
	local signatureBaseString = OAuthUtil.createSignatureBaseString(sortOrder, newRequestInformation)

	return `OAuth {signatureBaseString}` 
end

local new = OAuthUtil.new({
	consumerKey = "clientIdentifier",
	token = "accessT!oken",
	consumerSecret = "clientSecret",
	tokenSecret = "tokenSecret",
	callbackUrl = nil,
	signatureMethod = "HMAC-SHA1",
	requestType = "GET",
	requestUrl = "https://www.google.com/",
})

local newHeader = new:generateHeader("dskfm329sdam121",1424991993,"GET")

print(newHeader)

return OAuthUtil
