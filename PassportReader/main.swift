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
let ENCk = mrzHashPrefix + c1
let ENCkData = ENCk.data(using: .utf8)
let ENCkHash = sha1HashData(data: ENCkData!)
let ENCkHashPrefix = ENCkHash.prefix(32)
print("ENC Key : " + ENCkHashPrefix)

// Step 2.2 : Calculate MAC key by concat MrzHash with c2 and do SHA1 HASH again
let c2 = "00000002"
let MACk = mrzHashPrefix + c2
let MACkData = MACk.data(using: .utf8)
let MACkHash = sha1HashData(data: MACkData!)
let MACkHashPrefix = MACkHash.prefix(32)
print("MAC key : " + MACkHashPrefix)

// adjust parity bit

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
print(rndIFD)
print(kIFD)

// Step 3.4 : Concat rndIFD / rndIC / kIFD respectively
let s = rndIFD + /* rndIC + */ kIFD
print(s)

print(TripleDesEnc(input: "781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B", key: "AB94FDECF2674FDFB9B391F85D7F76F2"))
//B9B391F85D7F76F2

// 3DES Encryption
func TripleDesEnc(input:String,key:String) -> String {
    // Divide Input to 64 bit Block
    let strArr:[String] = DivideInputToEach64BitBlock(HexInput: input)
    // Divided Key
    let index = key.index(key.startIndex,offsetBy: 16)
    let firstKey:String = String(key[..<index])
    let secondKey:String = String(key[index...])
    
    // 1st Round
    let fBlockfRound = DESEnc(Input: strArr[0], Key: firstKey)
    // 2nd Round

    // 3rd Round
    
    return DESEnc(Input: input, Key: firstKey)
}

func DivideInputToEach64BitBlock(HexInput:String)->[String]{
    return HexInput.split(by: 16)
}

func DESEnc(Input:String,Key:String,Iv:String = "0000000000000000")->String{
    //MARK: Round 1 - Encryption
    let Option = UInt32(kCCEncrypt)
    let Algorithm = UInt32(kCCAlgorithmDES)
    //let Key = firstKey.hexadecimal! as NSData
    let Key = Key.hexadecimal! as NSData
    let KeyLength = size_t(kCCKeySizeDES)
    let Data = Input.hexadecimal! as NSData
    let iv = Iv.hexadecimal! as NSData
    let cryptData1 = NSMutableData(length: Int(Data.length))!
    var numBytesEncrypted :size_t = 0
    let cryptoStatus = CCCrypt(Option,Algorithm,0,Key.bytes,KeyLength,nil, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
    print(cryptoStatus)
    if UInt32(cryptoStatus) == UInt32(kCCSuccess) {
        //Convert NSMutualData to NSData to Data
        let data = NSData(data: cryptData1 as Data) as Data
        return data.hexadecimal
        
    }else{
        return "Fail"
    }
}

func DESDec(Input:String,Key:String,Iv:String = "0000000000000000")->String{
    //MARK: Round 1 - Encryption
    let Option = UInt32(kCCDecrypt)
    let Algorithm = UInt32(kCCAlgorithmDES)
    //let Key = firstKey.hexadecimal! as NSData
    let Key = Key.hexadecimal! as NSData
    let KeyLength = size_t(kCCKeySizeDES)
    let Data = Input.hexadecimal! as NSData
    let iv = Iv.hexadecimal! as NSData
    let cryptData1 = NSMutableData(length: Int(Data.length))!
    var numBytesEncrypted :size_t = 0
    let cryptoStatus = CCCrypt(Option,Algorithm,0,Key.bytes,KeyLength,nil, Data.bytes, Data.count, cryptData1.mutableBytes, cryptData1.length,&numBytesEncrypted)
    print(cryptoStatus)
    if UInt32(cryptoStatus) == UInt32(kCCSuccess) {
        //Convert NSMutualData to NSData to Data
        let data = NSData(data: cryptData1 as Data) as Data
        return data.hexadecimal
        
    }else{
        return "Fail"
    }
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


