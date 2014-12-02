//
//  This is free and unencumbered software released into the public domain.
//
//  Anyone is free to copy, modify, publish, use, compile, sell, or
//  distribute this software, either in source code form or as a compiled
//  binary, for any purpose, commercial or non-commercial, and by any
//  means.
//
//  In jurisdictions that recognize copyright laws, the author or authors
//  of this software dedicate any and all copyright interest in the
//  software to the public domain. We make this dedication for the benefit
//  of the public at large and to the detriment of our heirs and
//  successors. We intend this dedication to be an overt act of
//  relinquishment in perpetuity of all present and future rights to this
//  software under copyright law.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
//  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
//  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//  OTHER DEALINGS IN THE SOFTWARE.
//
//  For more information, please refer to <http://unlicense.org/>
//

#import "NSData+Crypto.h"

#import <CommonCrypto/CommonCrypto.h>

@interface NSData (Crypto_Private)

- (NSString*) digestForFunction:(unsigned char* (*)(const void*, CC_LONG, unsigned char*)) digestFunction length:(CC_LONG) digestLength;

@end

@implementation NSData (Crypto)

#pragma mark -
#pragma mark Self

- (NSString*) md2
{
	return [self digestForFunction:CC_MD2 length:CC_MD2_DIGEST_LENGTH];
}

- (NSString*) md4
{
	return [self digestForFunction:CC_MD4 length:CC_MD4_DIGEST_LENGTH];
}

- (NSString*) md5
{
	return [self digestForFunction:CC_MD5 length:CC_MD5_DIGEST_LENGTH];
}

- (NSString*) sha1
{
	return [self digestForFunction:CC_SHA1 length:CC_SHA1_DIGEST_LENGTH];
}

- (NSString*) sha224
{
	return [self digestForFunction:CC_SHA224 length:CC_SHA224_DIGEST_LENGTH];
}

- (NSString*) sha256
{
	return [self digestForFunction:CC_SHA256 length:CC_SHA256_DIGEST_LENGTH];
}

- (NSString*) sha384
{
	return [self digestForFunction:CC_SHA384 length:CC_SHA384_DIGEST_LENGTH];
}

- (NSString*) sha512
{
	return [self digestForFunction:CC_SHA512 length:CC_SHA512_DIGEST_LENGTH];
}

#pragma mark -
#pragma mark Private

- (NSString*) digestForFunction:(unsigned char* (*)(const void*, CC_LONG, unsigned char*)) digestFunction length:(CC_LONG) digestLength
{
	unsigned char digest[digestLength];
	digestFunction(self.bytes, (CC_LONG)self.length, digest);
	
	NSMutableString* result = [NSMutableString stringWithCapacity:(digestLength * 2)];
	
	for(CC_LONG i = 0; i < digestLength; i++)
		[result appendFormat:@"%02x", digest[i]];
	
	return [result copy];
}

@end
