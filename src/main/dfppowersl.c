#include "ghidra_import.h"

extern u32 GameBit_Get(int eventId);
extern void ObjHits_SetHitVolumeSlot(u8 *obj,int param_2,int param_3,int param_4);

extern undefined4 *lbl_803DCA54;
extern undefined4 *lbl_803DCA78;
extern undefined4 *pDll_expgfx;

typedef struct DfpPowerSlState {
  s32 activateObjectId;
  s32 spawnObjectId;
  s32 eventId;
} DfpPowerSlState;

typedef void (*DfpPowerSlFreeFn)(u8 *obj);
typedef void (*DfpPowerSlActivateFn)(u8 *obj,int objectId);
typedef void (*DfpPowerSlRefreshFn)(int param_1,u8 *obj,int param_3);
typedef void (*DfpPowerSlSpawnFn)(u8 *obj,int objectId,void *params,int param_4,int param_5,void *outObj);

undefined4 dfppowersl_spawnSeqObjectsOnHit(u8 *obj);

static inline DfpPowerSlState *dfppowersl_getState(u8 *obj)
{
  return *(DfpPowerSlState **)(obj + 0xb8);
}

int dfppowersl_getExtraSize(void)
{
  return sizeof(DfpPowerSlState);
}

#pragma scheduling off
#pragma peephole off
void dfppowersl_free(u8 *obj)
{
  if (obj != 0) {
    ((DfpPowerSlFreeFn)(*(u32 *)(*lbl_803DCA78 + 0x18)))(obj);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfppowersl_render(u8 *obj)
{
  u8 *powerSl;
  DfpPowerSlState *state;

  powerSl = obj;
  if ((u32)powerSl != 0) {
    state = dfppowersl_getState(powerSl);
    if (GameBit_Get(state->eventId) == 0) {
      ((DfpPowerSlSpawnFn)(*(u32 *)(*pDll_expgfx + 8)))(powerSl,state->spawnObjectId,0,4,
                                                         0xffffffff,0);
      ((DfpPowerSlSpawnFn)(*(u32 *)(*pDll_expgfx + 8)))(powerSl,state->spawnObjectId,0,1,
                                                         0xffffffff,0);
    }
  }
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfppowersl_update(u8 *obj)
{
  u8 *powerSl;
  DfpPowerSlState *state;

  powerSl = obj;
  if ((u32)powerSl != 0) {
    state = dfppowersl_getState(powerSl);
    ((DfpPowerSlActivateFn)(*(u32 *)(*lbl_803DCA54 + 0x54)))(powerSl,state->activateObjectId);
    ((DfpPowerSlRefreshFn)(*(u32 *)(*lbl_803DCA54 + 0x48)))(0,powerSl,0xffffffff);
  }
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfppowersl_init(u8 *obj,u8 *params)
{
  DfpPowerSlState *state;

  if (obj != 0) {
    state = dfppowersl_getState(obj);
    if (*(s16 *)(params + 0x1a) <= 0) {
      *(s16 *)(params + 0x1a) = 1;
    }
    if (*(s16 *)(params + 0x1c) <= 0) {
      *(s16 *)(params + 0x1c) = 1;
    }
    *(undefined4 **)(obj + 0xbc) = (undefined4 *)dfppowersl_spawnSeqObjectsOnHit;
    state->activateObjectId = *(s16 *)(params + 0x1a);
    state->spawnObjectId = *(s16 *)(params + 0x1c);
    state->eventId = *(s16 *)(params + 0x20);
    *(s16 *)obj = *(s8 *)(params + 0x18) << 8;
    ObjHits_SetHitVolumeSlot(obj,0x13,1,0);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
