#ifndef MAIN_SPELLSTONE_H_
#define MAIN_SPELLSTONE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

/* SpellStoneState.state */
typedef enum SpellStoneStateId {
  SPELLSTONE_STATE_HIDDEN = 0, /* not rendered, hits off, snaps to follow target */
  SPELLSTONE_STATE_IDLE = 1,   /* placed and visible, hits enabled, awaiting activation */
  SPELLSTONE_STATE_ACTIVE = 2  /* raised and spinning, proximity-completes the map event */
} SpellStoneStateId;

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
  f32 worldPosX; /* 0x18: world position, distance-checked against the player (Vec_distance vs playerObj+0x18) */
  f32 worldPosY; /* 0x1c */
  f32 worldPosZ; /* 0x20 */
  u8 unk24[0x28];
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
void spellstone_render(SpellStoneObject *obj,u32 param_2,u32 param_3,
                       u32 param_4,u32 param_5,char visible);
void spellstone_hitDetect(void);
void spellstone_update(SpellStoneObject *obj);
void spellstone_init(SpellStoneObject *obj);
void spellstone_release(void);
void spellstone_initialise(void);

#endif /* MAIN_SPELLSTONE_H_ */
