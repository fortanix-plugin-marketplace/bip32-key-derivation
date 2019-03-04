--[[/* Copyright [2019] [Fortanix, Inc.]
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
* http://www.apache.org/licenses/LICENSE-2.0 ]]--
 
-- constant
local PRIVATE_WALLET_VERSION =  "0488ADE4"
local PUBLIC_WALLET_VERSION = "0488B21E"
local FIRST_HARDENED_CHILD = 2147483648
local N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

-- key structure
local key = {
    ["version"] = "",
    ["depth"] = "",       -- 1 byte
    ["index"] = "",       -- 4 byte child number
    ["fingerprint"] = "", -- 4 byte parent fingerprint
    ["chainCode"] = "",   -- 32 byte
    ["key"] = "",         -- 33 byte long key
    ["checksum"] = "",    -- checksum of all above
    ["isPrivate"] = ""    -- 1 bit flag
}

function numToHex(num, size)
    local hexstr = '0123456789ABCDEF'
    local s = ""
    while num > 0 do
        local mod = math.fmod(num, 16)
        s = string.sub(hexstr, mod+1, mod+1) .. s
        num = math.floor(num / 16)
    end
    if (string.len(s) < size) then
        local offset = string.rep("0", size-string.len(s))
        s = offset..s
    end
    return s
end

-- split string on pattern
function split(str, pat)
    local t = {}
    local fpat = "(.-)" .. pat
    local lastEnd = 1
    local s, e, cap = str:find(fpat, 1)
    while s do
        if s ~= 1 or cap ~= "" then
            table.insert(t,cap)
        end
        lastEnd = e+1
        s, e, cap = str:find(fpat, lastEnd)
    end
    if lastEnd <= #str then
        cap = str:sub(lastEnd)
        table.insert(t, cap)
    end
    return t
end

-- encode BIP key into ASN1 format
function createASN1privateKey(keybyte)
    return "302E0201010420".. keybyte .."A00706052B8104000A"
end

-- import ASN1 encoded key
function importECKey(blob)
    local sobject = assert(Sobject.import { name = "ec", obj_type = "EC", elliptic_curve = "SecP256K1", value = blob, transient = true })
    return sobject
end

-- extract co-ordinate from complete ec public key
function extractCoordinatesFromASN1PublicKey(keybyte)
    return string.sub(keybyte, 49, 176)
end

-- return ec curve co-ordinate from private key
-- y-coordinate: first 32 byte from end x-coordinate next 32 byte
function GetPointCoordinatesFromPrivateKey(keybyte)
    local asn1ECKey = createASN1privateKey(keybyte)
    local blob = Blob.from_hex(asn1ECKey)
    local ecKey = importECKey(blob)
    local asn1PublicKey = ecKey.pub_key:hex()
    local coordinate = extractCoordinatesFromASN1PublicKey(asn1PublicKey)
    return coordinate
end

-- compress key co-ordinate
function compressPublicKey(x, y)
    local a = BigNum.from_bytes_be(Blob.from_hex(y))
    local b = BigNum.from_bytes_be(Blob.from_hex("02"))
    local c = BigNum.from_bytes_be(Blob.from_hex("00"))

    a:mod(b)

    if a:to_bytes_be()[1] == "" then
        return "02"..x
    else
        return "03"..x
    end
end

-- public key from private key
function publicKeyForPrivateKey(keybyte)
    local point = GetPointCoordinatesFromPrivateKey(keybyte)
    return compressPublicKey(string.sub(point, 1, 64), string.sub(point, 65, 128))
end

-- parse input path
function parsePath(childPath)
    local pathTable = split(childPath, "/")
    return pathTable
end

-- return hex of exported key
function decodeKey(exportedMasterSerializedKey)
    local blob = Blob.from_base58(exportedMasterSerializedKey)
    return blob:hex()
end

-- export BIP32 master key from SDKMS ---
function exportSecretKey(keyId)
    return Sobject { kid = keyId }:export().value
end

-- import chain-code as hmac key
-- sign data from hmac key
function getHmac(hmacKey, data)
    local sobject = assert(Sobject.import { name = "hmac", obj_type = "HMAC", value = Blob.from_hex(hmacKey), transient = true })
    local mac =  assert(sobject:mac { data = Blob.from_hex(data), alg = 'SHA512'}).digest
    return mac:hex()
end

-- RIPMD160 digest
function hash160(data)
    local sha256Hash = assert(digest { data = Blob.from_hex(data), alg = 'SHA256' }).digest
    local ripmd160Hash = assert(digest { data = sha256Hash, alg = 'RIPEMD160' }).digest
    return ripmd160Hash:hex()
end

-- add private keys
function addPrivateKeys(k1, k2)
    local a = BigNum.from_bytes_be(Blob.from_hex(k1))
    local b = BigNum.from_bytes_be(Blob.from_hex(k2))
    a:add(b)
    a:mod(BigNum.from_bytes_be(Blob.from_hex(N)))
    hexKey = a:to_bytes_be():hex()
    if (string.len( hexKey ) < 66) then
        local offset = string.rep("0", 32-string.len( hexKey ))
        hexKey = offset..hexKey
    end
    return hexKey
end

-- scalar addition of point
--[[function addPublicKeys(k1, k2)
    local point2 = GetPointCoordinatesFromPrivateKey(k1)
    local point2 = GetPointCoordinatesFromPrivateKey(k2)
    local p1 = EcPoint.from_components(string.sub(point1, 1, 32), string.sub(point1, 33, 64))
    local p2 = EcPoint.from_components(string.sub(point2, 1, 32), string.sub(point2, 33, 64))
    return p1+p2
end ]]--

-- checksum: double SHA256 of serialized key
function getCheckSum(childKey)
    local chlidKeyString = childKey.version.. childKey.depth..  childKey.fingerprint.. childKey.index.. childKey.chainCode.. childKey.key
    local sha256Hash1 = assert(digest { data = Blob.from_hex(chlidKeyString), alg = 'SHA256' }).digest:hex()
    local sha256Hash2 = assert(digest { data =  Blob.from_hex(sha256Hash1), alg = 'SHA256' }).digest:hex()
    return sha256Hash2
end

-- deserialize BIP key
function deserialize(exportedMasterSerializedKey)
    hexKey = decodeKey(exportedMasterSerializedKey)

    key.version = string.sub(hexKey, 1, 8)
    key.depth = string.sub(hexKey, 9, 10)
    key.index = string.sub(hexKey, 11, 18)
    key.fingerprint = string.sub(hexKey, 19, 26)
    key.chainCode = string.sub(hexKey, 27, 90)
    key.key = string.sub(hexKey, 91, 156)

    if key.version == PRIVATE_WALLET_VERSION then
        key.isPrivate = 1
    else
        key.isPrivate = 0
    end

    key.checksum = string.sub(hexKey, 157, 164)
    return key
end

-- derive new child key from parent key
function deriveNewChild(parentKey, childIdx)
    local data = ""
    -- if index is greater than equal to first hardened key
    if tonumber(childIdx) >= FIRST_HARDENED_CHILD then
        data = parentKey.key
    else
        -- parent key is private
        -- data equal to public key of parent private
        if parentKey.isPrivate then
            data = publicKeyForPrivateKey(string.sub(parentKey.key, 3, 66))
        else
            -- parent key is public
            -- data equal to parent key
            data = parentKey.key
        end
    end

    -- concatenate index into data
    local indexHex = numToHex(childIdx, 8)
    data = data..indexHex
    hmac = getHmac(parentKey.chainCode, data)

    childKey = {
        index = indexHex,
        chainCode = string.sub(hmac, 65, 128),
        depth = numToHex(tonumber(parentKey.depth + 1), 2),
        isPrivate = parentKey.isPrivate,
    }

    if parentKey.isPrivate then
        childKey.version = PRIVATE_WALLET_VERSION
        fingerprint = hash160(publicKeyForPrivateKey(string.sub(parentKey.key, 3, 66)))
        childKey.fingerprint = string.sub(fingerprint, 1, 8)
        -- appending 00 to make key size 33 bit
        childKey.key = "00"..tostring(addPrivateKeys(string.sub(hmac, 1, 64), parentKey.key))
    --[[ else
        -- TODO: Test Me
        childKey.Version = PUBLIC_WALLET_VERSION
        fingerprint = hash160(parentKey.key)
        childKey.fingerprint = string.sub(fingerprint, 1, 8)
        keyBytes = publicKeyForPrivateKey(string.sub(hmac, 1, 64))
        childKey.Key = addPublicKeys(keyBytes, parentKey.Key)
    end ]]--

    return childKey
end

-- serialize child key and encode into base58
function serialize(childKey)
    childKey.checksum = string.sub(getCheckSum(childKey), 1, 8)
    local chlidKeyString = table.concat({childKey.version, childKey.depth, childKey.fingerprint, childKey.index,
        childKey.chainCode, childKey.key, childKey.checksum}
    )
    local blob = Blob.from_hex(chlidKeyString)
    return  blob:base58()
end

-- xpub key from xprv
function getPublicKey(childKey)
    local pubKey = publicKeyForPrivateKey(string.sub(childKey.key, 3, 66))
    childKey.version = PUBLIC_WALLET_VERSION
    childKey.key = pubKey
    return serialize(childKey)
end

-- main method
function run(input)
    local exportedMasterSerializedKey = exportSecretKey(input.masterKeyId)
    local masterKey = deserialize(exportedMasterSerializedKey:bytes())
    local indices = parsePath(input.path)

    for i = 2, #indices do
        childKey = deriveNewChild(masterKey, tonumber(indices[i]))
        masterKey = childKey
    end

    local childKeySerialized = serialize(childKey)
    local publicKey = getPublicKey(childKey)

    return {
        privateKey = childKeySerialized,
        publicKey = publicKey,
    }
end
