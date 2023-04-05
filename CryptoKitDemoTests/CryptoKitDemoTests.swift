//
//  CryptoKitDemoTests.swift
//  CryptoKitDemoTests
//
//  Created by Arslan Raza on 05/04/2023.
//

import XCTest
import CryptoKit
@testable import CryptoKitDemo

final class CryptoKitDemoTests: XCTestCase {
    
    let key = SymmetricKey(size: .bits256)
    let userAPrivateKey = P521.KeyAgreement.PrivateKey()
    var userBPublicKey: P521.KeyAgreement.PublicKey?
    let userBPrivateKey = P521.KeyAgreement.PrivateKey()
    var userAPublicKey: P521.KeyAgreement.PublicKey?
    var userASymmetricKey: SymmetricKey?
    var userBSymmetricKey: SymmetricKey?
    var encryptedData: Data?
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    //    AES algorithm encryption and decryption of string using symmetricKey
    
    func testEncryptionAndDecryption() {
        //        encryption
        
        let stringToEncrypt = "create encrypted data"
        let message = stringToEncrypt.data(using: .utf8)!
        
        let sealedBox = try! AES.GCM.seal(message, using: key)
        let encryptedData = sealedBox.combined
        
        XCTAssertNotNil(encryptedData)
        
        //        decryption
        
        let DecryptedSealedBox = try! AES.GCM.SealedBox(combined: encryptedData!)
        let decryptedData = try? AES.GCM.open(DecryptedSealedBox, using: key)
        let decryptedString = String(data: decryptedData ?? Data(), encoding: .utf8) ?? ""
        
        XCTAssertEqual(decryptedString, stringToEncrypt)
        
    }
    
    
    //    AES algorithm encryption and decryption of image using symmetricKey
    
    func testEncryptionAndDecryptionUsingImage() {
        
//        encryption
        
        guard let filePath = Bundle(for: type(of: self)).path(forResource: "testImage", ofType: "png"),
              let image = UIImage(contentsOfFile: filePath),
              let imageData = image.pngData() else {
            fatalError("Image not available")
        }
        let sealedBox = try! AES.GCM.seal(imageData, using: key)
        let encryptedData = sealedBox.combined
        
        XCTAssertNotNil(encryptedData)
        
//        decryption
        
        let sealedBoxToDecryptedData = try! AES.GCM.SealedBox(combined: encryptedData!)
        let decryptedData = try! AES.GCM.open(sealedBoxToDecryptedData, using: key)
        let decryptedImage = UIImage(data: decryptedData)
        
        XCTAssertEqual(decryptedImage?.pngData(), imageData)
        
    }
    
    //    encryption and decryption using receiver publicKey
    
    func testEncryptionAndDecryptionUsing() {
        // Derive keys using the salt value
        
//        encryption
        
        userAPublicKey = userAPrivateKey.publicKey
        userBPublicKey = userBPrivateKey.publicKey
        
        if let salt = "Our Value For Salt".data(using: .utf8) {
            
            if let userASharedSecret = try? userAPrivateKey.sharedSecretFromKeyAgreement(with: userBPublicKey!) {
                userASymmetricKey = userASharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
                
                let message = "create encrypted data".data(using: .utf8)!
                let sealedBox = try! AES.GCM.seal(message, using: userASymmetricKey!)
                let encrypted = sealedBox.combined!
                encryptedData = encrypted
            }
        }
        
        
//        decryption
        
        if let salt = "Our Value For Salt".data(using: .utf8) {
            if let userBSharedSecret = try? userBPrivateKey.sharedSecretFromKeyAgreement(with: userAPublicKey!) {
                userBSymmetricKey = userBSharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
                
                let sealedBox = try! AES.GCM.SealedBox(combined: encryptedData!)
                let decryptedData = try? AES.GCM.open(sealedBox, using: userBSymmetricKey!)
                let decryptedString = String(data: decryptedData ?? Data(), encoding: .utf8) ?? ""
                
                print(decryptedString)
                
                if userASymmetricKey == userBSymmetricKey {
                    print("Keys are equal. Let's share data.")
                }
            }
        }
    }
}
