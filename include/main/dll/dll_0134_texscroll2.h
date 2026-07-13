#ifndef MAIN_DLL_DLL_0134_TEXSCROLL2_H_
#define MAIN_DLL_DLL_0134_TEXSCROLL2_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor11WithPadding gTexscroll2ObjDescriptor;
extern ObjectDescriptor gTexscrollObjDescriptor;

#define TEXSCROLL2_DLL_ID 0x0134
#define TEXSCROLL_DLL_ID 0x0135
#define TEXSCROLL_CLASS_ID 0x0021
#define TEXSCROLL2_DEF_ID 0x04AF
#define TEXSCROLL_DEF_ID 0x04AE
#define TEXSCROLL_OBJECT_DEF_BYTES 0xA0
#define TEXSCROLL_PLACEMENT_BYTES 0x24
#define TEXSCROLL2_EXTRA_STATE_BYTES 0x18
#define TEXSCROLL_EXTRA_STATE_BYTES 0x1C

#define TEXSCROLL_TABLE_ID 0x0E
#define TEXSCROLL_SLOT_UNALLOCATED 0xFF
#define TEXSCROLL_GAMEBIT_GATED_MAP_A 0x49B2F
#define TEXSCROLL_GAMEBIT_GATED_MAP_B 0x49B67

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

typedef struct TexScroll2State {
  u8 pad00[8];
  s32 gameBit;
  s32 previousGameBitValue;
  u8 needsApply;
  s8 stepX;
  s8 stepY;
  s8 secondaryStepX;
  s8 secondaryStepY;
  u8 pad15[3];
} TexScroll2State;

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

typedef struct TexScroll2Object {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  TexScroll2State *state;
} TexScroll2Object;

typedef struct TexScrollObject {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  TexScrollState *state;
} TexScrollObject;

STATIC_ASSERT(sizeof(TexScrollPlacement) == TEXSCROLL_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(TexScrollPlacement, mapId) == 0x14);
STATIC_ASSERT(offsetof(TexScrollPlacement, textureTableIndex) == 0x18);
STATIC_ASSERT(offsetof(TexScrollPlacement, gameBit) == 0x1A);
STATIC_ASSERT(offsetof(TexScrollPlacement, secondaryStepX) == 0x1C);
STATIC_ASSERT(offsetof(TexScrollPlacement, secondaryStepY) == 0x1D);
STATIC_ASSERT(offsetof(TexScrollPlacement, stepX) == 0x1E);
STATIC_ASSERT(offsetof(TexScrollPlacement, stepY) == 0x1F);
STATIC_ASSERT(sizeof(TexScroll2State) == TEXSCROLL2_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(TexScroll2State, gameBit) == 0x08);
STATIC_ASSERT(offsetof(TexScroll2State, previousGameBitValue) == 0x0C);
STATIC_ASSERT(offsetof(TexScroll2State, needsApply) == 0x10);
STATIC_ASSERT(offsetof(TexScroll2State, stepX) == 0x11);
STATIC_ASSERT(offsetof(TexScroll2State, stepY) == 0x12);
STATIC_ASSERT(offsetof(TexScroll2State, secondaryStepX) == 0x13);
STATIC_ASSERT(offsetof(TexScroll2State, secondaryStepY) == 0x14);
STATIC_ASSERT(sizeof(TexScrollState) == TEXSCROLL_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(TexScrollState, initLock) == 0x02);
STATIC_ASSERT(offsetof(TexScrollState, stepX) == 0x04);
STATIC_ASSERT(offsetof(TexScrollState, stepY) == 0x06);
STATIC_ASSERT(offsetof(TexScrollState, offsetX) == 0x08);
STATIC_ASSERT(offsetof(TexScrollState, offsetY) == 0x0A);
STATIC_ASSERT(offsetof(TexScrollState, scrollSlot) == 0x0C);
STATIC_ASSERT(offsetof(TexScrollState, gameBit) == 0x14);
STATIC_ASSERT(offsetof(TexScrollState, flags) == 0x18);
STATIC_ASSERT(offsetof(TexScroll2Object, state) == 0xB8);
STATIC_ASSERT(offsetof(TexScrollObject, state) == 0xB8);

void texscroll2_setScale(TexScroll2Object *obj, s8 scale);
void texscroll2_update(TexScroll2Object *obj);
void texscroll2_init(TexScroll2Object *obj, TexScrollPlacement *placement, int loadFlags);
void texscroll_init(TexScrollObject *obj, TexScrollPlacement *placement, int loadFlags);

#endif /* MAIN_DLL_DLL_0134_TEXSCROLL2_H_ */
