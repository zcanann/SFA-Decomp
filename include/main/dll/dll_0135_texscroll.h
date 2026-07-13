#ifndef MAIN_DLL_DLL_0135_TEXSCROLL_H_
#define MAIN_DLL_DLL_0135_TEXSCROLL_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/texscroll_types.h"

extern ObjectDescriptor gTexscrollObjDescriptor;

#define TEXSCROLL_EXTRA_STATE_BYTES 0x1C

typedef struct TexScrollState {
  u8 pad00[2];
  s16 initLock;
  s16 stepX;
  s16 stepY;
  s16 offsetX;
  s16 offsetY;
  s32 scrollSlot;
  u8 pad10[4];
  s16 gameBit;
  u8 pad16[2];
  u8 flags;
  u8 pad19[3];
} TexScrollState;

typedef struct TexScrollObject {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  TexScrollState *state;
} TexScrollObject;

STATIC_ASSERT(sizeof(TexScrollState) == TEXSCROLL_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(TexScrollState, initLock) == 0x02);
STATIC_ASSERT(offsetof(TexScrollState, stepX) == 0x04);
STATIC_ASSERT(offsetof(TexScrollState, stepY) == 0x06);
STATIC_ASSERT(offsetof(TexScrollState, offsetX) == 0x08);
STATIC_ASSERT(offsetof(TexScrollState, offsetY) == 0x0A);
STATIC_ASSERT(offsetof(TexScrollState, scrollSlot) == 0x0C);
STATIC_ASSERT(offsetof(TexScrollState, gameBit) == 0x14);
STATIC_ASSERT(offsetof(TexScrollState, flags) == 0x18);
STATIC_ASSERT(offsetof(TexScrollObject, state) == 0xB8);

void texscroll_init(TexScrollObject *obj, TexScrollPlacement *placement, int loadFlags);

#endif /* MAIN_DLL_DLL_0135_TEXSCROLL_H_ */
