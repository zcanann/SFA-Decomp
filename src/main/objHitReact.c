#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"

extern int Sfx_IsPlayingFromObject(int obj,u16 sfxId);
extern void Sfx_PlayFromObject(int obj,u16 sfxId);
extern void fn_80013E2C(void *handle);
extern int *fn_8002E0FC(undefined *param_1,undefined *param_2);
extern void fn_8009A1DC(double param_1,int obj,undefined2 *pos,u32 count,int *param_5);

typedef struct ObjHitReactEffectOrigin { undefined4 m[4]; } ObjHitReactEffectOrigin;
extern ObjHitReactEffectOrigin lbl_802C1B00;
extern char sObjHitReactHitstateFrameString[];
extern char sObjHitReactSphereOverflowString[];
extern char sObjHitReactResetString[7];
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
#define OBJHITREACT_COLLISION_SKIP_REACTION 0x11
#define OBJHITREACT_HIT_FX_MODE_EFFECT 1
#define OBJHITREACT_HIT_EFFECT_ID 0x5A
#define OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS 0x401
#define OBJHITREACT_RESET_FRAME_COUNT 0x400

extern ObjHitReactEffectHandle *fn_80013EC8(u32 effectId,u32 count);

/*
 * --INFO--
 *
 * Function: objHitReact_update
 * EN v1.0 Address: 0x800353A4
 * EN v1.0 Size: 652b
 */
#pragma scheduling off
#pragma peephole off
int objHitReact_update(int obj,ObjHitReactEntry *entries,u32 entryCount,u32 reactionState,float *cooldown)
{
  ObjAnimComponent *objAnim;
  ObjAnimDef *animDef;
  int collisionType;
  ObjHitReactEffectHandle *effectHandle;
  bool sfxActive;
  f32 hitPos[3];
  ObjHitReactEffectPos effectPos;
  ObjHitReactEffectOrigin effectOrigin;
  int sphereIndex;

  objAnim = (ObjAnimComponent *)obj;
  effectOrigin = lbl_802C1B00;
  if ((reactionState & 0xff) != 0) {
    OSReport(sObjHitReactHitstateFrameString,objAnim->currentMoveProgress);
    collisionType = ObjAnim_AdvanceCurrentMove((double)*cooldown,(double)lbl_803DB414,obj,
                                               (ObjAnimEventList *)0x0);
    if (collisionType != 0) {
      OSReport(sObjHitReactResetString);
      reactionState = 0;
    }
  }
  collisionType = ObjHits_GetPriorityHitWithPosition(obj,0,&sphereIndex,0,&hitPos[0],&hitPos[1],&hitPos[2]);
  if (collisionType != 0) {
    ObjAnimBank *bank = ObjAnim_GetActiveBank(objAnim);
    hitPos[0] = hitPos[0] + lbl_803DCDD8;
    hitPos[2] = hitPos[2] + lbl_803DCDDC;
    effectPos.scale = lbl_803DE918;
    effectPos.z = 0;
    effectPos.y = 0;
    effectPos.x = 0;
    animDef = bank->animDef;
    sphereIndex = ObjAnim_GetHitReactEntryIndex(animDef,sphereIndex);
    if (sphereIndex >= (int)(entryCount & 0xff)) {
      OSReport(sObjHitReactSphereOverflowString);
      sphereIndex = 0;
    }
    entries = &entries[sphereIndex];
    if (collisionType != OBJHITREACT_COLLISION_SKIP_REACTION) {
      if ((entries->hitSfxA > -1) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)entries->hitSfxA), !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)entries->hitSfxA);
      }
      if ((entries->hitSfxB > -1) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)entries->hitSfxB), !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)entries->hitSfxB);
      }
      if (entries->hitFxMode == OBJHITREACT_HIT_FX_MODE_EFFECT) {
        effectHandle = fn_80013EC8(OBJHITREACT_HIT_EFFECT_ID,1);
        effectHandle->vtable->spawn(0,1,&effectPos,OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,-1,&effectOrigin);
        if (effectHandle != (ObjHitReactEffectHandle *)0x0) {
          fn_80013E2C(effectHandle);
        }
      }
      else {
        fn_8009A1DC((double)lbl_803DE964,obj,(undefined2 *)&effectPos.x,1,0);
      }
    }
    if (((reactionState & 0xff) == 0) && (entries->reactionAnim > -1)) {
      ObjAnim_SetCurrentMove((double)lbl_803DE910,obj,(int)entries->reactionAnim,0);
      *cooldown = entries->cooldown;
      reactionState = 1;
    }
  }
  return reactionState;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
          if (gObjHitReactResetObjectCount < OBJHITREACT_MAX_RESET_OBJECTS) {
            resetObjects = gObjHitReactResetObjects;
            resetObjectCount = gObjHitReactResetObjectCount;
            gObjHitReactResetObjectCount = resetObjectCount + 1;
            resetObjects[resetObjectCount] = obj;
          }
          hitState->activeHit = 0;
          hitState->flags = (s16)(hitState->flags & ~OBJHITREACT_STATE_RESET_PENDING);
          hitState->resetFrameCount = OBJHITREACT_RESET_FRAME_COUNT;
        }
      }
    }
    objectList = objectList + 1;
    objectCount = objectCount + -1;
  }
}
#pragma peephole reset
#pragma scheduling reset
