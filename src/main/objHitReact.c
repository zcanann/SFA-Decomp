#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"

extern int Sfx_IsPlayingFromObject(int obj,u16 sfxId);
extern void Sfx_PlayFromObject(int obj,u16 sfxId);
extern void Resource_Release(void *handle);
extern int *ObjList_GetObjects(undefined *param_1,undefined *param_2);
extern void fn_8009A1DC(int obj,double scale,undefined2 *pos,u32 count,int *param_5);

extern ObjHitReactEffectOrigin lbl_802C1B00;
extern char sObjHitReactHitstateFrameString[];
extern char sObjHitReactSphereOverflowString[];
extern char sObjHitReactResetString[7];
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DE910;
extern f32 lbl_803DE918;
extern f32 lbl_803DE964;
extern int gObjHitReactResetObjectCount;
extern int *gObjHitReactResetObjects;

extern ObjHitReactEffectHandle *Resource_Acquire(u32 effectId,u32 count);

/*
 * --INFO--
 *
 * Function: objHitReact_update
 * EN v1.0 Address: 0x800353A4
 * EN v1.0 Size: 652b
 */
#pragma scheduling off
#pragma peephole off
int objHitReact_update(int obj,ObjHitReactEntry *reactionEntries,u32 reactionEntryCount,
                       u32 reactionState,float *reactionStepScale)
{
  u32 currentReactionState;
  ObjAnimDef *animDef;
  int moveEnded;
  int priorityHitType;
  ObjHitReactEffectHandle *effectHandle;
  bool sfxActive;
  f32 hitPos[3];
  ObjHitReactEffectPos effectPos;
  ObjHitReactEffectOrigin effectOrigin;
  int hitSphereIndex;

  currentReactionState = reactionState;
  effectOrigin = lbl_802C1B00;
  if ((currentReactionState & OBJHITREACT_REACTION_STATE_MASK) != OBJHITREACT_REACTION_STATE_INACTIVE) {
    OSReport(sObjHitReactHitstateFrameString,((ObjAnimComponent *)obj)->currentMoveProgress);
    moveEnded = ObjAnim_AdvanceCurrentMove((double)*reactionStepScale,(double)timeDelta,
                                           obj,(ObjAnimEventList *)0x0);
    if (moveEnded != 0) {
      OSReport(sObjHitReactResetString);
      currentReactionState = OBJHITREACT_REACTION_STATE_INACTIVE;
    }
  }
  priorityHitType = ObjHits_GetPriorityHitWithPosition(obj,0,&hitSphereIndex,0,&hitPos[0],
                                                       &hitPos[1],&hitPos[2]);
  if (priorityHitType != 0) {
    ObjAnimBank *bank = ObjAnim_GetActiveBank((ObjAnimComponent *)obj);
    hitPos[0] = hitPos[0] + playerMapOffsetX;
    hitPos[2] = hitPos[2] + playerMapOffsetZ;
    effectPos.scale = lbl_803DE918;
    effectPos.z = 0;
    effectPos.y = 0;
    effectPos.x = 0;
    animDef = bank->animDef;
    hitSphereIndex = ObjAnim_GetHitReactEntryIndex(animDef,hitSphereIndex);
    if (hitSphereIndex >= (int)(reactionEntryCount & 0xff)) {
      OSReport(sObjHitReactSphereOverflowString);
      hitSphereIndex = 0;
    }
    reactionEntries = &reactionEntries[hitSphereIndex];
    if (priorityHitType != OBJHITREACT_COLLISION_SKIP_REACTION) {
      if ((reactionEntries->hitSfxA > OBJHITREACT_NO_SFX_ID) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)reactionEntries->hitSfxA),
          !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)reactionEntries->hitSfxA);
      }
      if ((reactionEntries->hitSfxB > OBJHITREACT_NO_SFX_ID) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)reactionEntries->hitSfxB),
          !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)reactionEntries->hitSfxB);
      }
      if (reactionEntries->hitFxMode == OBJHITREACT_HIT_FX_MODE_EFFECT) {
        effectHandle = Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID,1);
        effectHandle->vtable->spawn(0,1,&effectPos,OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,-1,&effectOrigin);
        if (effectHandle != (ObjHitReactEffectHandle *)0x0) {
          Resource_Release(effectHandle);
        }
      }
      else {
        fn_8009A1DC(obj,(double)lbl_803DE964,(undefined2 *)&effectPos.x,1,0);
      }
    }
    if (((currentReactionState & OBJHITREACT_REACTION_STATE_MASK) == OBJHITREACT_REACTION_STATE_INACTIVE) &&
        (reactionEntries->reactionAnim > OBJHITREACT_NO_REACTION_ANIM)) {
      ObjAnim_SetCurrentMove(lbl_803DE910,obj,(int)reactionEntries->reactionAnim,0);
      *reactionStepScale = reactionEntries->cooldown;
      currentReactionState = OBJHITREACT_REACTION_STATE_ACTIVE;
    }
  }
  return currentReactionState;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_ResetActiveObjects
 * EN v1.0 Address: 0x80035630
 * EN v1.0 Size: 192b
 */
#pragma scheduling off
#pragma peephole off
void ObjHitReact_ResetActiveObjects(int objectCount)
{
  ObjHitReactState *hitState;
  int obj;
  int *objectList;
  int stateActive;
  int resetPending;
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
            gObjHitReactResetObjects[gObjHitReactResetObjectCount++] = obj;
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
