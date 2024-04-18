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
	consumerSecret: string, 
	callbackUrl: string?,
	token: string?,
	tokenSecret: string?,
	requestUrl: string,
	requestType: string,
	signatureMethod: "PLAINTEXT" | "HMAC-SHA1" | "HMAC-SHA256" | "HMAC-SHA512",
}

local OAuthUtil = {
	--CONFIGURATION
	nonceLength = 15, --Recommended: 11-15. Messing with this is not recommended unless you know what you're doing.
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

OAuthUtil.convertHexToString = function(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
	
OAuthUtil.encodeString = function(strToEncode: string): string
	local encodedStr = string.gsub(strToEncode, "[^%w%-%._~']", function(char)
		return `%{string.format("%X", string.byte(char))}`
	end)
	return encodedStr
end

local function encodeHeader(array: {}): nil
	for index, value in pairs(array) do
		array[index] = OAuthUtil.encodeString(value) 
	end

	return array
end

--SIGNATURES
OAuthUtil.signatureEncoding = {
	["PLAINTEXT"] = function(consumerSecret, tokenSecret)
		if tokenSecret then
			return OAuthUtil.encodeString(consumerSecret) .. "&" .. OAuthUtil.encodeString(tokenSecret)
		else
			return OAuthUtil.encodeString(consumerSecret) .. "&"
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
function OAuthUtil:generateNonce(_retries: number?): string
	if _retries and _retries > 15 then error(`Nonce (Random String) generation reached max of: {_retries} retries.`) end

	local nonce = HttpService:GenerateGUID(false)

	if table.find(self.usedNonces,nonce) then
		if not _retries then _retries = 0 end

		return OAuthUtil:generateNonce(_retries+1)
	else
		table.insert(self.usedNonces,nonce)
		return nonce
	end
end

function OAuthUtil.createSignatureBaseString(sortOrder, OAuthHeader, useAmpersand: boolean)	
	local newArray = {}

	for index,headerIndex in pairs(sortOrder) do
		if not OAuthHeader[headerIndex] then warn(headerIndex .. "not found with OAuthHeader!") continue end

		newArray[#newArray+1] = headerIndex
		newArray[#newArray+1] = "="
		newArray[#newArray+1] = OAuthHeader[headerIndex]

		if index ~= #sortOrder then
			newArray[#newArray+1] = useAmpersand and "&" or ","
		end
	end

	return table.concat(newArray)
end

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
		["requestType"] = parameters.requestType,
 		["requestUrl"] = parameters.requestUrl, -- example
		["usedNonces"] = {},
	}

	setmetatable(requestInformation, OAuthUtil)

	return requestInformation
end

function OAuthUtil:setRequestUrl(requestUrl: string): nil
	self["requestUrl"] = requestUrl
end

function OAuthUtil:setRequestType(requestType: string): nil
	self["requestType"] = requestType
end

function OAuthUtil:setTokenSecret(tokenSecret: string): nil
	self["oauth_token_secret"] = tokenSecret
end

function OAuthUtil:setToken(token: string): nil
	self["oauth_token"] = token
end

function OAuthUtil:createSignature(newRequestInformation: string): string
	local encodedParameters = encodeHeader(table.clone(newRequestInformation))
	local sortOrder = sortParameters(encodedParameters)

	local methodUrlString = `{OAuthUtil.encodeString(self.requestType)}&{OAuthUtil.encodeString(self.requestUrl)}`
	local baseParameterString = OAuthUtil.createSignatureBaseString(sortOrder, encodedParameters, true)

	baseParameterString = OAuthUtil.encodeString(baseParameterString)

	local signatureBaseString = methodUrlString .. "&"  .. baseParameterString
	local oauth_signature = generateSignature(self.parameters.oauth_signature_method,self.oauth_consumer_secret,self.oauth_token_secret, signatureBaseString)
	oauth_signature = (self.parameters.oauth_signature_method~="PLAINTEXT") and OAuthUtil.encodeString(base64.encode(OAuthUtil.convertHexToString(oauth_signature))) or oauth_signature

	return oauth_signature
end

function OAuthUtil:generateHeader(overrideNonce: string, overrideTimestamp: number): string
	local newRequestInformation = table.clone(self.parameters)
	
	newRequestInformation["oauth_nonce"] = overrideNonce or OAuthUtil:generateNonce()
	newRequestInformation["oauth_timestamp"] = overrideTimestamp or os.time()
	newRequestInformation["oauth_signature"]  = self:createSignature(newRequestInformation,self.requestType)

	local sortOrder = sortParameters(newRequestInformation)
	
	local signatureBaseString = OAuthUtil.createSignatureBaseString(sortOrder, newRequestInformation)

	return `OAuth {signatureBaseString}` 
end

return OAuthUtil
