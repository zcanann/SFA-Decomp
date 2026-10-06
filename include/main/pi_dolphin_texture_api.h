#ifndef MAIN_PI_DOLPHIN_TEXTURE_API_H_
#define MAIN_PI_DOLPHIN_TEXTURE_API_H_

#include "types.h"

#define TEXTURE_FRAME_QUERY_HEADER         0
#define TEXTURE_FRAME_QUERY_INDEXED_HEADER 1
#define TEXTURE_FRAME_QUERY_OFFSETS        2

/* bankWord's low 24 bits are a halfword offset into the selected archive.
 * INDEXED_HEADER reads the frame at frameOffsets[frameIndexOrCount].
 * OFFSETS copies frameIndexOrCount + 1 entries, including the end offset.
 * Other modes, or a NULL frameOffsets pointer, read the first header.
 * Only non-indexed TEX1/TEXPRE queries return compressedSize == -1 for DIR.
 * If no archive is resident, the output arguments are left untouched. */
void tex0GetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode);
void tex1GetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                  int* frameOffsets, int queryMode);
void texPreGetFrame(int bankWord, int unused, int* decompressedSize, int* compressedSize, int frameIndexOrCount,
                    int* frameOffsets, int queryMode);
void freeAndNull(void** p);
#endif /* MAIN_PI_DOLPHIN_TEXTURE_API_H_ */
