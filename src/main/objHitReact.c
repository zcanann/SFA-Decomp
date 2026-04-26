#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern int fn_8000B5D0(int obj,u16 volumeId);
extern void fn_8000BB18(int obj,u16 volumeId);
extern void fn_80013E2C(void *handle);
extern int *fn_8002E0FC(undefined *param_1,undefined *param_2);
extern int fn_80036770(int obj,undefined4 *param_2,int *sphereIndex,uint *param_4,float *hitPos,
                       undefined *param_6,float *param_7);
extern void fn_8009A1DC(double param_1,int obj,undefined2 *pos,u32 count,int *param_5);

extern undefined4 lbl_802C1B00[4];
extern char sObjHitReactHitstateFrameString[];
extern char sObjHitReactSphereOverflowString[];
extern char sObjHitReactResetString[];
extern f32 lbl_803DB414;
extern f32 lbl_803DCDD8;
extern f32 lbl_803DCDDC;
extern f32 lbl_803DE910;
extern f32 lbl_803DE918;
extern f32 lbl_803DE964;
extern int gObjHitReactResetObjectCount;
extern int *gObjHitReactResetObjects;

typedef struct ObjHitReactEffectPos {
  s16 x;
  s16 y;
  s16 z;
  u8 pad06[2];
  f32 scale;
} ObjHitReactEffectPos;

typedef struct ObjHitReactEffectVTable {
  code pad00;
  code spawn;
} ObjHitReactEffectVTable;

typedef struct ObjHitReactEffectHandle {
  ObjHitReactEffectVTable *vtable;
} ObjHitReactEffectHandle;

#define OBJHITREACT_STATE_ACTIVE 0x01
#define OBJHITREACT_STATE_RESET_PENDING 0x08

extern ObjHitReactEffectHandle *fn_80013EC8(u32 effectId,u32 count);

/*
 * --INFO--
 *
 * Function: objHitReact_update
 * EN v1.0 Address: 0x800353A4
 * EN v1.0 Size: 652b
 */
#pragma scheduling off
int objHitReact_update(int obj,void *entries,u32 entryCount,u32 reactionState,float *cooldown)
{
  ObjAnimComponent *objAnim;
  ObjAnimDef *animDef;
  int collisionType;
  ObjHitReactEffectHandle *effectHandle;
  bool volumeActive;
  ObjHitReactEntry *reactEntry;
  float hitNormalY;
  undefined local_24[4];
  float local_28;
  ObjHitReactEffectPos effectPos;
  undefined4 effectOrigin[4];
  int sphereIndex;

  objAnim = (ObjAnimComponent *)obj;
  effectOrigin[0] = lbl_802C1B00[0];
  effectOrigin[1] = lbl_802C1B00[1];
  effectOrigin[2] = lbl_802C1B00[2];
  effectOrigin[3] = lbl_802C1B00[3];
  if ((reactionState & 0xff) != 0) {
    OSReport(sObjHitReactHitstateFrameString,objAnim->currentMoveProgress);
    collisionType = ObjAnim_AdvanceCurrentMove((double)*cooldown,(double)lbl_803DB414,obj,
                                               (ObjAnimEventList *)0x0);
    if (collisionType != 0) {
      OSReport(sObjHitReactResetString);
      reactionState = 0;
    }
  }
  collisionType = fn_80036770(obj,0,&sphereIndex,0,&local_28,local_24,&hitNormalY);
  if (collisionType != 0) {
    animDef = ObjAnim_GetAnimDef(objAnim);
    local_28 = local_28 + lbl_803DCDD8;
    hitNormalY = hitNormalY + lbl_803DCDDC;
    effectPos.scale = lbl_803DE918;
    effectPos.x = 0;
    effectPos.y = 0;
    effectPos.z = 0;
    sphereIndex = ObjAnim_GetHitReactEntryIndex(animDef,sphereIndex);
    if ((int)(entryCount & 0xff) <= sphereIndex) {
      OSReport(sObjHitReactSphereOverflowString);
      sphereIndex = 0;
    }
    reactEntry = (ObjHitReactEntry *)((u8 *)entries + sphereIndex * sizeof(ObjHitReactEntry));
    if (collisionType != 0x11) {
      if ((reactEntry->clearVolumeA > -1) &&
          (volumeActive = fn_8000B5D0(obj,(u16)reactEntry->clearVolumeA), !volumeActive)) {
        fn_8000BB18(obj,(u16)reactEntry->clearVolumeA);
      }
      if ((reactEntry->clearVolumeB > -1) &&
          (volumeActive = fn_8000B5D0(obj,(u16)reactEntry->clearVolumeB), !volumeActive)) {
        fn_8000BB18(obj,(u16)reactEntry->clearVolumeB);
      }
      if (reactEntry->hitFxMode == 1) {
        effectHandle = fn_80013EC8(0x5a,1);
        effectHandle->vtable->spawn(0,1,&effectPos,0x401,-1,effectOrigin);
        if (effectHandle != (ObjHitReactEffectHandle *)0x0) {
          fn_80013E2C(effectHandle);
        }
      }
      else {
        fn_8009A1DC((double)lbl_803DE964,obj,(undefined2 *)&effectPos.x,1,0);
      }
    }
    if (((reactionState & 0xff) == 0) && (reactEntry->reactionAnim > -1)) {
      ObjAnim_SetCurrentMove((double)lbl_803DE910,obj,(int)reactEntry->reactionAnim,0);
      *cooldown = reactEntry->cooldown;
      reactionState = 1;
    }
  }
  return reactionState;
}
#pragma scheduling reset

#pragma scheduling off
void ObjHitReact_ResetActiveObjects(int objectCount)
{
  ObjHitReactState *hitState;
  int obj;
  int *objectList;
  int *resetObjects;
  int stateActive;
  int resetPending;
  int resetObjectCount;
  undefined local_14[4];
  undefined local_18[4];

  objectList = fn_8002E0FC(local_18,local_14);
  gObjHitReactResetObjectCount = 0;
  while (objectCount > 0) {
    obj = *objectList;
    hitState = ((ObjAnimComponent *)obj)->hitReactState;
    if (hitState != (ObjHitReactState *)0x0) {
      stateActive = hitState->flags & OBJHITREACT_STATE_ACTIVE;
      if (stateActive != 0) {
        resetPending = hitState->resetFlags & OBJHITREACT_STATE_RESET_PENDING;
        if (resetPending != 0) {
          if (gObjHitReactResetObjectCount < 0x32) {
            resetObjectCount = gObjHitReactResetObjectCount;
            resetObjects = gObjHitReactResetObjects;
            gObjHitReactResetObjectCount = resetObjectCount + 1;
            resetObjects[resetObjectCount] = obj;
          }
          hitState->activeHit = 0;
          hitState->flags = (s16)(hitState->flags & ~OBJHITREACT_STATE_RESET_PENDING);
          hitState->resetFrameCount = 0x400;
        }
      }
    }
    objectList = objectList + 1;
    objectCount = objectCount + -1;
  }
}
#pragma scheduling reset
