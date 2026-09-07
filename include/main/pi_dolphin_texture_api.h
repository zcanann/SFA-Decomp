#ifndef MAIN_PI_DOLPHIN_TEXTURE_API_H_
#define MAIN_PI_DOLPHIN_TEXTURE_API_H_

#include "types.h"

#define TEXTURE_FRAME_QUERY_HEADER         0
#define TEXTURE_FRAME_QUERY_INDEXED_HEADER 1
#define TEXTURE_FRAME_QUERY_OFFSETS        2

void tex0GetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode);
void tex1GetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode);
void texPreGetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode);
void freeAndNull(void** p);
#endif /* MAIN_PI_DOLPHIN_TEXTURE_API_H_ */
