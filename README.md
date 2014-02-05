NSData+Crypto
===========

`NSData+Crypto` is a Mac and iOS `NSData` and `NSString` wrapper for the CommonCrypto framework's digest methods.

The following digest functions are wrapped:
- md2
- md4
- md5
- sha1
- sha224
- sha256
- sha384
- sha512

All digest functions are available for `NSData`, `NSString`, and on files - read in chunks so a file of any size can be digested.

Usage
-----

    [@"hello" md5];
    [[NSData dataWithContentsOfFile:@"/file"] md5];
    [NSString md5WithContentsOfFile:@"/file"];
