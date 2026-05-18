#ifndef MAIN_SPELLSTONE_H_
#define MAIN_SPELLSTONE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct SpellStoneState {
  u8 state;
} SpellStoneState;

typedef struct SpellStoneDef {
  u8 unk0[0x19];
  s8 eventIndex;
  u8 unk1A[4];
  s16 completeEvent;
  s16 activeEvent;
} SpellStoneDef;

typedef struct SpellStoneObject {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  s16 flags;
  u8 unk8[4];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk18[0x34];
  SpellStoneDef *def;
  u8 unk50[0x68];
  SpellStoneState *state;
  int (*callback)(void);
  u8 unkC0[4];
  void *followTarget;
} SpellStoneObject;

extern ObjectDescriptor12 gSpellStoneObjDescriptor;

int spellstone_getState(SpellStoneObject *obj);
int spellstone_setState(SpellStoneObject *obj,int state);
int spellstone_getExtraSize(void);
int spellstone_func08(void);
void spellstone_free(SpellStoneObject *obj);
void spellstone_render(SpellStoneObject *obj,undefined4 param_2,undefined4 param_3,
                       undefined4 param_4,undefined4 param_5,char visible);
void spellstone_hitDetect(void);
void spellstone_update(SpellStoneObject *obj);
void spellstone_init(SpellStoneObject *obj);
void spellstone_release(void);
void spellstone_initialise(void);

#endif /* MAIN_SPELLSTONE_H_ */
