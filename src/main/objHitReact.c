#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"

extern int Sfx_IsPlayingFromObject(int obj,u16 sfxId);
extern void Sfx_PlayFromObject(int obj,u16 sfxId);
extern void fn_80013E2C(void *handle);
extern int *ObjList_GetObjects(undefined *param_1,undefined *param_2);
extern void fn_8009A1DC(double param_1,int obj,undefined2 *pos,u32 count,int *param_5);

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
int objHitReact_update(ObjAnimComponent *obj,ObjHitReactEntry *entryTable,u32 entryCount,
                       u32 reactionState,float *cooldown)
{
  ObjAnimComponent *objAnim;
  int objHandle;
  ObjAnimDef *animDef;
  int hitType;
  ObjHitReactEffectHandle *effectHandle;
  bool sfxActive;
  f32 hitPos[3];
  ObjHitReactEffectPos effectPos;
  ObjHitReactEffectOrigin effectOrigin;
  int hitSphereIndex;
  int entryIndex;

  objAnim = obj;
  objHandle = (int)obj;
  effectOrigin = lbl_802C1B00;
  if ((reactionState & 0xff) != 0) {
    OSReport(sObjHitReactHitstateFrameString,objAnim->currentMoveProgress);
    hitType = ObjAnim_AdvanceCurrentMove((double)*cooldown,(double)lbl_803DB414,objHandle,
                                         (ObjAnimEventList *)0x0);
    if (hitType != 0) {
      OSReport(sObjHitReactResetString);
      reactionState = 0;
    }
  }
  hitType = ObjHits_GetPriorityHitWithPosition(objHandle,0,&hitSphereIndex,0,&hitPos[0],
                                               &hitPos[1],&hitPos[2]);
  if (hitType != 0) {
    ObjAnimBank *bank = ObjAnim_GetActiveBank(objAnim);
    hitPos[0] = hitPos[0] + lbl_803DCDD8;
    hitPos[2] = hitPos[2] + lbl_803DCDDC;
    effectPos.scale = lbl_803DE918;
    effectPos.z = 0;
    effectPos.y = 0;
    effectPos.x = 0;
    animDef = bank->animDef;
    entryIndex = ObjAnim_GetHitReactEntryIndex(animDef,hitSphereIndex);
    if (entryIndex >= (int)(entryCount & 0xff)) {
      OSReport(sObjHitReactSphereOverflowString);
      entryIndex = 0;
    }
    entryTable = &entryTable[entryIndex];
    if (hitType != OBJHITREACT_COLLISION_SKIP_REACTION) {
      if ((entryTable->hitSfxA > -1) &&
          (sfxActive = Sfx_IsPlayingFromObject(objHandle,(u16)entryTable->hitSfxA), !sfxActive)) {
        Sfx_PlayFromObject(objHandle,(u16)entryTable->hitSfxA);
      }
      if ((entryTable->hitSfxB > -1) &&
          (sfxActive = Sfx_IsPlayingFromObject(objHandle,(u16)entryTable->hitSfxB), !sfxActive)) {
        Sfx_PlayFromObject(objHandle,(u16)entryTable->hitSfxB);
      }
      if (entryTable->hitFxMode == OBJHITREACT_HIT_FX_MODE_EFFECT) {
        effectHandle = fn_80013EC8(OBJHITREACT_HIT_EFFECT_ID,1);
        effectHandle->vtable->spawn(0,1,&effectPos,OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,-1,&effectOrigin);
        if (effectHandle != (ObjHitReactEffectHandle *)0x0) {
          fn_80013E2C(effectHandle);
        }
      }
      else {
        fn_8009A1DC((double)lbl_803DE964,objHandle,(undefined2 *)&effectPos.x,1,0);
      }
    }
    if (((reactionState & 0xff) == 0) && (entryTable->reactionAnim > -1)) {
      ObjAnim_SetCurrentMove((double)lbl_803DE910,objHandle,(int)entryTable->reactionAnim,0);
      *cooldown = entryTable->cooldown;
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

  objectList = ObjList_GetObjects(local_18,local_14);
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
