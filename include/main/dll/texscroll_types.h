#ifndef MAIN_DLL_TEXSCROLL_TYPES_H_
#define MAIN_DLL_TEXSCROLL_TYPES_H_

#include "global.h"

#define TEXSCROLL_PLACEMENT_BYTES 0x24

typedef struct TexScrollPlacement {
  u8 pad00[0x14];
  s32 mapId;
  s16 textureTableIndex;
  s16 gameBit;
  s8 secondaryStepX;
  s8 secondaryStepY;
  s8 stepX;
  s8 stepY;
  u8 pad20[TEXSCROLL_PLACEMENT_BYTES - 0x20];
} TexScrollPlacement;

STATIC_ASSERT(sizeof(TexScrollPlacement) == TEXSCROLL_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(TexScrollPlacement, mapId) == 0x14);
STATIC_ASSERT(offsetof(TexScrollPlacement, textureTableIndex) == 0x18);
STATIC_ASSERT(offsetof(TexScrollPlacement, gameBit) == 0x1A);
STATIC_ASSERT(offsetof(TexScrollPlacement, secondaryStepX) == 0x1C);
STATIC_ASSERT(offsetof(TexScrollPlacement, secondaryStepY) == 0x1D);
STATIC_ASSERT(offsetof(TexScrollPlacement, stepX) == 0x1E);
STATIC_ASSERT(offsetof(TexScrollPlacement, stepY) == 0x1F);

#endif /* MAIN_DLL_TEXSCROLL_TYPES_H_ */
