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

#import "NSString+Crypto.h"

#import <CommonCrypto/CommonCrypto.h>

#import "NSData+Crypto.h"

@interface NSString (Crypto_Private)

+ (instancetype) digestWithContentsOfFile:(NSString*) path withContext:(void*) context initFunction:(int(*)(void*)) initFunction updateFunction:(int(*)(void*, const void*, CC_LONG)) updateFunction finalFunction:(int(*)(unsigned char*, void*)) finalFunction length:(CC_LONG) digestLength;

@end

@implementation NSString (Crypto)

+ (instancetype) md2WithContentsOfFile:(NSString*) path
{
	CC_MD2_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_MD2_Init updateFunction:(void*)CC_MD2_Update finalFunction:(void*)CC_MD2_Final length:CC_MD2_DIGEST_LENGTH];
}

+ (instancetype) md4WithContentsOfFile:(NSString*) path
{
	CC_MD4_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_MD4_Init updateFunction:(void*)CC_MD4_Update finalFunction:(void*)CC_MD4_Final length:CC_MD4_DIGEST_LENGTH];
}

+ (instancetype) md5WithContentsOfFile:(NSString*) path
{
	CC_MD5_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_MD5_Init updateFunction:(void*)CC_MD5_Update finalFunction:(void*)CC_MD5_Final length:CC_MD5_DIGEST_LENGTH];
}

+ (instancetype) sha1WithContentsOfFile:(NSString*) path
{
	CC_SHA1_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_SHA1_Init updateFunction:(void*)CC_SHA1_Update finalFunction:(void*)CC_SHA1_Final length:CC_SHA1_DIGEST_LENGTH];
}

+ (instancetype) sha224WithContentsOfFile:(NSString*) path
{
	CC_SHA256_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_SHA224_Init updateFunction:(void*)CC_SHA224_Update finalFunction:(void*)CC_SHA224_Final length:CC_SHA224_DIGEST_LENGTH];
}

+ (instancetype) sha256WithContentsOfFile:(NSString*) path
{
	CC_SHA256_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_SHA256_Init updateFunction:(void*)CC_SHA256_Update finalFunction:(void*)CC_SHA256_Final length:CC_SHA256_DIGEST_LENGTH];
}

+ (instancetype) sha384WithContentsOfFile:(NSString*) path
{
	CC_SHA512_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_SHA384_Init updateFunction:(void*)CC_SHA384_Update finalFunction:(void*)CC_SHA384_Final length:CC_SHA384_DIGEST_LENGTH];
}

+ (instancetype) sha512WithContentsOfFile:(NSString*) path
{
	CC_SHA512_CTX context;
	return [self digestWithContentsOfFile:path withContext:&context initFunction:(void*)CC_SHA512_Init updateFunction:(void*)CC_SHA512_Update finalFunction:(void*)CC_SHA512_Final length:CC_SHA512_DIGEST_LENGTH];
}

#pragma mark -
#pragma mark Self

- (NSString*) md2
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] md2];
}

- (NSString*) md4
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] md4];
}

- (NSString*) md5
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] md5];
}

- (NSString*) sha1
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] sha1];
}

- (NSString*) sha224
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] sha224];
}

- (NSString*) sha256
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] sha256];
}

- (NSString*) sha384
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] sha384];
}

- (NSString*) sha512
{
	return [[self dataUsingEncoding:NSUTF8StringEncoding] sha512];
}

#pragma mark -
#pragma mark Private

+ (instancetype) digestWithContentsOfFile:(NSString*) path withContext:(void*) context initFunction:(int(*)(void*)) initFunction updateFunction:(int(*)(void*, const void*, CC_LONG)) updateFunction finalFunction:(int(*)(unsigned char*, void*)) finalFunction length:(CC_LONG) digestLength
{
	FILE* fileHandle = fopen(path.UTF8String, "rb");
	
	if(fileHandle == NULL)
		return nil;
	
	const unsigned int bufferSize = 16384;
	unsigned char buffer[bufferSize];
	
	initFunction(context);
	
	while(YES)
	{
		//	Read the file in chunks so a file of any size can be digested
		const size_t readSize = fread(buffer, 1, sizeof(buffer), fileHandle);
		updateFunction(context, buffer, (CC_LONG)readSize);
		
		if(readSize <= 0)
			break;
	}
	
	fclose(fileHandle);
	
	unsigned char digest[digestLength];
	finalFunction(digest, context);
	
	NSMutableString* output = [NSMutableString stringWithCapacity:(digestLength * 2)];
	
	for(CC_LONG i = 0; i < digestLength; i++)
		[output appendFormat:@"%02x", digest[i]];
	
	return [self stringWithString:output];
}

@end
