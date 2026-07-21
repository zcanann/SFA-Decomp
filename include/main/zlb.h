#ifndef MAIN_ZLB_H_
#define MAIN_ZLB_H_

#define ZLB_FIXED_LITERAL_SYMBOL_COUNT 288
#define ZLB_FIXED_LITERAL_TABLE_SIZE   512
#define ZLB_FIXED_DISTANCE_SYMBOL_COUNT 32
#define ZLB_BIT_REVERSE_TABLE_SIZE     256

extern unsigned char gInflateFixedLiteralCodeLengths[ZLB_FIXED_LITERAL_SYMBOL_COUNT];
extern unsigned short gInflateFixedLiteralDecodeTable[ZLB_FIXED_LITERAL_TABLE_SIZE];
extern unsigned char gInflateFixedDistanceCodeLengths[ZLB_FIXED_DISTANCE_SYMBOL_COUNT];
extern unsigned char gInflateFixedDistanceDecodeTable[ZLB_FIXED_DISTANCE_SYMBOL_COUNT];
extern unsigned char gInflateBitReverseTable[ZLB_BIT_REVERSE_TABLE_SIZE];

int zlbDecompress(unsigned char* compressedData, int compressedSize, unsigned char* destination, void* decompressedSize);

#endif /* MAIN_ZLB_H_ */
