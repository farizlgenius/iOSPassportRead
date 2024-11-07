//
//  main.swift
//  PassportReader
//
//  Created by Far-iz Lengha on 1/11/2567 BE.
//

import Foundation
import CryptoTokenKit
import CryptoKit
import CommonCrypto


let mrz = "AA4296977286080552003197"

// MARK: Step 01
// Step 1.1 : Used SHA1 for hash mrz data
let mrzData = mrz.data(using: .utf8)
let Kseed = sha1HashData(data: mrzData!)
print(Kseed)


// SHA1 Hash function
func sha1HashData(data:Data) -> String{
    let hashData = Insecure.SHA1.hash(data: data)
    let hashString = hashData.compactMap{
        String(format: "%02X", $0)
    }.joined()
    return hashString
}

// Step 1.2 : Get only 32 length of hash data
let mrzHashPrefix = Kseed.prefix(32)
print(mrzHashPrefix)


//MARK: Step 02

// Step 2.1 : Calculate encryption key by concat MrzHash with c1 and do SHA1 HASH again
let c1 = "00000001"
let Kenc = mrzHashPrefix + c1
let KencData = Kenc.data(using: .utf8)
let KencHash = sha1HashData(data: KencData!)
let KencHashPrefix = KencHash.prefix(32)
print("ENC Key : " + KencHashPrefix)

// Step 2.2 : Calculate MAC key by concat MrzHash with c2 and do SHA1 HASH again
let c2 = "00000002"
let Kmac = mrzHashPrefix + c2
let KmacData = Kmac.data(using: .utf8)
let KmacHash = sha1HashData(data: KmacData!)
let KmacHashPrefix = KmacHash.prefix(32)
print("MAC key : " + KmacHashPrefix)

// adjust parity bit
let ENCkAdj = AdjustParity(key: String(KencHashPrefix))
print("ENC Adjust Key : " + ENCkAdj)

let MACkadj = AdjustParity(key: String(KmacHashPrefix))
print("MAC Adjust Key : " + MACkadj)

//MARK: Step 03
// Step 3.1 : Send APDU Command to passport for select DF in passport

// Step 3.2 : Get rndIC from APDU Command

// Step 3.3 : Random 8 byte data / Randome 16 byte data
let hexStr = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]
var rndIFD:String = ""
var kIFD:String = ""
for _ in 0..<16 {
    rndIFD = rndIFD + hexStr[Int.random(in: 0..<16)]
}
for _ in 0..<32 {
    kIFD = kIFD + hexStr[Int.random(in: 0..<16)]
}


// Step 3.4 : Concat rndIFD / rndIC / kIFD respectively
let S = rndIFD + /* rndIC + */ kIFD
print(S)


// Step 3.5 : Encrypt s on 3DES CBC with Kenc
let Eifd = TripleDesEncCBC(input: S, key: String(Kenc))

// Step 3.6 : Calculate Mac with Kmac
let Mifd = MessageAuthenticationCodeMethodTwo(input: Eifd,key: String(Kmac))

// Step 4 : Construct command and send to reader
// APDU Command : 0082000028 + cmd_data + 28

let cmdData = Eifd + Mifd

// Step 4.1 : Decrypt 
print(TripleDesDecCBC(input: "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F", key: "AB94FDECF2674FDFB9B391F85D7F76F2"))



/*
######################### Utility is below ###############################
 */
// MARK: 3DES Encryption
// 3DES Encryption
func TripleDesEncCBC(input:String,key:String) -> String {
    // Divide Input to 64 bit Block
    let strArr:[String] = DivideInputToEach64BitBlock(HexInput: input)
    // Divided Key
    let index = key.index(key.startIndex,offsetBy: 16)
    let firstKey:String = String(key[..<index])
    let secondKey:String = String(key[index...])
    // Set count for loop array
    let count = 0...(strArr.count-1)
    var result:[String] = []
    // 1st Round
    for i in count {
        if i == 0 {
            result.append(DESEncECB(Input: DESDecECB(Input: DESEncCBC(Input: strArr[i], key: firstKey), key: secondKey), key: firstKey))
        }else{
            result.append(DESEncECB(Input: DESDecECB(Input: DESEncCBC(Input: strArr[i], key: firstKey,Iv: result[i-1]), key: secondKey), key: firstKey))
        }
    }
    return result.joined().uppercased()
}

// 3DES Decryption
func TripleDesDecCBC(input:String,key:String) -> String {
    // Divide Input to 64 bit Block
    let strArr:[String] = DivideInputToEach64BitBlock(HexInput: input)
    // Divided Key
    let index = key.index(key.startIndex,offsetBy: 16)
    let firstKey:String = String(key[..<index])
    let secondKey:String = String(key[index...])
    // Set count for loop array
    let count = 0...(strArr.count-1)
    var result:[String] = []
    // 1st Round
    for i in count {
        if i == 0 {
            result.append(DESDecCBC(Input: DESEncECB(Input: DESDecECB(Input: strArr[i], key: firstKey), key: secondKey), key: firstKey))
        }else{
            result.append(DESDecCBC(Input: DESEncECB(Input: DESDecECB(Input: strArr[i], key: firstKey), key: secondKey), key: firstKey,Iv: strArr[i-1]))
        }
    }
    return result.joined().uppercased()
}

// MARK: MAC Algorithm
func MessageAuthenticationCodeMethodOne(input:String,key:String)->String{
    // Divided key
    let index = key.index(key.startIndex,offsetBy: 16)
    let firstKey:String = String(key[..<index])
    let secondKey:String = String(key[index...])
    //Perform Des CBC mode for full length
    let first = DESEncCBC(Input: input, key: firstKey)
    // Divide Input to 64 bit Block
    let strArr:[String] = DivideInputToEach64BitBlock(HexInput: first)
    //Perform full on remain
    let result = DESEncCBC(Input: DESDecCBC(Input: strArr[strArr.count-1], key: secondKey), key: firstKey)
    return result.uppercased()
}

func MessageAuthenticationCodeMethodTwo(input:String,key:String)->String{
    // Bit Padding
    let input2 = input + "8000000000000000"
    print("input2 : " + input2)
    // Divided key
    let index = key.index(key.startIndex,offsetBy: 16)
    let firstKey:String = String(key[..<index])
    let secondKey:String = String(key[index...])
    //Perform Des CBC mode for full length
    let first = DESEncCBC(Input: input2, key: firstKey)
    // Divide Input to 64 bit Block
    let strArr:[String] = DivideInputToEach64BitBlock(HexInput: first)
    //Perform full on remain
    let result = DESEncCBC(Input: DESDecCBC(Input: strArr[strArr.count-1], key: secondKey), key: firstKey)
    return result.uppercased()
}

func DivideInputToEach64BitBlock(HexInput:String)->[String]{
    return HexInput.split(by: 16)
}

func DivideInputToEach8BitBlock(HexInput:String)->[String]{
    return HexInput.split(by: 8)
}

func DESEncCBC(Input:String,key:String,Iv:String = "0000000000000000")->String{
    let Option = UInt32(kCCEncrypt)
    let Algorithm = UInt32(kCCAlgorithmDES)
    let Key = key.hexadecimal! as NSData
    let KeyLength = size_t(kCCKeySizeDES)
    let Data = Input.hexadecimal! as NSData
    let iv = Iv.hexadecimal! as NSData
    let cryptData1 = NSMutableData(length: Int(Data.length))!
    var numBytesEncrypted :size_t = 0
    let cryptoStatus = CCCrypt(Option,Algorithm,0,Key.bytes,KeyLength,iv.bytes, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
    if UInt32(cryptoStatus) == UInt32(kCCSuccess) {
        //Convert NSMutualData to NSData to Data
        let data = NSData(data: cryptData1 as Data) as Data
        return data.hexadecimal
        
    }else{
        return "Fail"
    }
}

func DESDecCBC(Input:String,key:String,Iv:String = "0000000000000000")->String{
    //MARK: Round 1 - Encryption
    let Option = UInt32(kCCDecrypt)
    let Algorithm = UInt32(kCCAlgorithmDES)
    let Key = key.hexadecimal! as NSData
    let KeyLength = size_t(kCCKeySizeDES)
    let Data = Input.hexadecimal! as NSData
    let iv = Iv.hexadecimal! as NSData
    let cryptData1 = NSMutableData(length: Int(Data.length))!
    var numBytesEncrypted :size_t = 0
    let cryptoStatus = CCCrypt(Option,Algorithm,0,Key.bytes,KeyLength,iv.bytes, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
    if UInt32(cryptoStatus) == UInt32(kCCSuccess) {
        //Convert NSMutualData to NSData to Data
        let data = NSData(data: cryptData1 as Data) as Data
        return data.hexadecimal
        
    }else{
        return "Fail"
    }
}

func DESEncECB(Input:String,key:String)->String{
    let Option = UInt32(kCCEncrypt)
    let Algorithm = UInt32(kCCAlgorithmDES)
    let Key = key.hexadecimal! as NSData
    let KeyLength = size_t(kCCKeySizeDES)
    let Data = Input.hexadecimal! as NSData
    let cryptData1 = NSMutableData(length: Int(Data.length))!
    var numBytesEncrypted :size_t = 0
    let cryptoStatus = CCCrypt(Option,Algorithm,UInt32(kCCOptionECBMode),Key.bytes,KeyLength,nil, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
    if UInt32(cryptoStatus) == UInt32(kCCSuccess) {
        //Convert NSMutualData to NSData to Data
        let data = NSData(data: cryptData1 as Data) as Data
        return data.hexadecimal
        
    }else{
        return "Fail"
    }
}

func DESDecECB(Input:String,key:String)->String{
    let Option = UInt32(kCCDecrypt)
    let Algorithm = UInt32(kCCAlgorithmDES)
    let Key = key.hexadecimal! as NSData
    let KeyLength = size_t(kCCKeySizeDES)
    let Data = Input.hexadecimal! as NSData
    let cryptData1 = NSMutableData(length: Int(Data.length))!
    var numBytesEncrypted :size_t = 0
    let cryptoStatus = CCCrypt(Option,Algorithm,UInt32(kCCOptionECBMode),Key.bytes,KeyLength,nil, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
    if UInt32(cryptoStatus) == UInt32(kCCSuccess) {
        //Convert NSMutualData to NSData to Data
        let data = NSData(data: cryptData1 as Data) as Data
        return data.hexadecimal
        
    }else{
        return "Fail"
    }
}

// Adjust parity bit for key
func AdjustParity(key:String)->String {
    let binArr = DivideInputToEach8BitBlock(HexInput: key.hexaToBinary)
    var result:[String] = []
    var result2:[String] = []
    for data in binArr {
        var count = 0
        var binn:[Character] = []
        for bit in data {
            binn.append(bit)
            if bit == "1" {
                count += 1
            }
        }
        if count % 2 == 0{
            if binn[binn.count-1] == "1" {
                binn[binn.count-1] = "0"
            }else{
                binn[binn.count-1] = "1"
            }
        }
        result.append(String(binn))
    }
    for bin in result {
        result2.append(binToHex(bin)!)
    }
    return result2.joined()
}




// Hex String to Data
extension String {
    
    /// Create `Data` from hexadecimal string representation
    ///
    /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
    ///
    /// - returns: Data represented by this hexadecimal string.
    
    var hexadecimal: Data? {
        var data = Data(capacity: count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        
        guard data.count > 0 else { return nil }
        
        return data
    }
    
    func split(by length: Int) -> [String] {
            var startIndex = self.startIndex
            var results = [Substring]()

            while startIndex < self.endIndex {
                let endIndex = self.index(startIndex, offsetBy: length, limitedBy: self.endIndex) ?? self.endIndex
                results.append(self[startIndex..<endIndex])
                startIndex = endIndex
            }

            return results.map { String($0) }
        }
    
}


// Data to Hex String
extension Data {
    
    /// Hexadecimal string representation of `Data` object.
    
    var hexadecimal: String {
        return map { String(format: "%02x", $0) }
            .joined()
    }
    
    public mutating func xor(key: Data) {
        for i in 0..<self.count {
            self[i] ^= key[i % key.count]
        }
    }


    public func checkSum() -> Int {
        return self.map { Int($0) }.reduce(0, +) & 0xff
    }
}

// Hex to binary
extension String {
    typealias Byte = UInt8
    var hexaToBytes: [Byte] {
        var start = startIndex
        return stride(from: 0, to: count, by: 2).compactMap { _ in   // use flatMap for older Swift versions
            let end = index(after: start)
            defer { start = index(after: end) }
            return Byte(self[start...end], radix: 16)
        }
    }
    var hexaToBinary: String {
        return hexaToBytes.map {
            let binary = String($0, radix: 2)
            return repeatElement("0", count: 8-binary.count) + binary
        }.joined()
    }
}

// Binary to hex
func binToHex(_ bin : String) -> String? {
    // binary to integer:
    guard let num = UInt64(bin, radix: 2) else { return nil }
    // integer to hex:
    let hex = String(num, radix: 16,uppercase: true) // (or false)
    if hex.count < 2 {
        let h = "0" + hex
        return h
    }
    return hex
}


