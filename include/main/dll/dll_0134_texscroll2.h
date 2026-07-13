#ifndef MAIN_DLL_DLL_0134_TEXSCROLL2_H_
#define MAIN_DLL_DLL_0134_TEXSCROLL2_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/texscroll_types.h"

extern ObjectDescriptor11WithPadding gTexscroll2ObjDescriptor;

#define TEXSCROLL2_EXTRA_STATE_BYTES 0x18

#define TEXSCROLL_TABLE_ID 0x0E
#define TEXSCROLL_SLOT_UNALLOCATED 0xFF
#define TEXSCROLL_GAMEBIT_GATED_MAP_A 0x49B2F
#define TEXSCROLL_GAMEBIT_GATED_MAP_B 0x49B67

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

typedef struct TexScroll2Object {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  TexScroll2State *state;
} TexScroll2Object;

STATIC_ASSERT(sizeof(TexScroll2State) == TEXSCROLL2_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(TexScroll2State, gameBit) == 0x08);
STATIC_ASSERT(offsetof(TexScroll2State, previousGameBitValue) == 0x0C);
STATIC_ASSERT(offsetof(TexScroll2State, needsApply) == 0x10);
STATIC_ASSERT(offsetof(TexScroll2State, stepX) == 0x11);
STATIC_ASSERT(offsetof(TexScroll2State, stepY) == 0x12);
STATIC_ASSERT(offsetof(TexScroll2State, secondaryStepX) == 0x13);
STATIC_ASSERT(offsetof(TexScroll2State, secondaryStepY) == 0x14);
STATIC_ASSERT(offsetof(TexScroll2Object, state) == 0xB8);

void texscroll2_setScale(TexScroll2Object *obj, s8 scale);
void texscroll2_update(TexScroll2Object *obj);
void texscroll2_init(TexScroll2Object *obj, TexScrollPlacement *placement, int loadFlags);

#endif /* MAIN_DLL_DLL_0134_TEXSCROLL2_H_ */
