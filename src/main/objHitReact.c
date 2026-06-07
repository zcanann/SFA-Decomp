#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objlib.h"
#include "main/resource.h"

extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void objLightFn_8009a1dc(int obj,double scale,ObjHitReactEffectPos *pos,u32 count,
                                int *params);

/*
 * --INFO--
 *
 * Function: ObjHitReact_Update
 * EN v1.0 Address: 0x800353A4
 * EN v1.0 Size: 652b
 */
#pragma scheduling off
#pragma peephole off
int ObjHitReact_Update(int obj,ObjHitReactEntry *reactionEntryTable,u32 reactionEntryCount,
                       u32 reactionState,float *reactionStepScale)
{
  ObjAnimDef *animDef;
  ObjAnimComponent *objAnim;
  int moveEnded;
  int hitType;
  ObjHitReactEntry *reactionEntry;
  ObjHitReactEffectHandle *effectHandle;
  bool sfxActive;
  f32 hitPos[3];
  ObjHitReactEffectPos effectPos;
  ObjHitReactEffectColorArgs effectColorArgs;
  int hitSphereIndex;

  objAnim = (ObjAnimComponent *)obj;
  effectColorArgs = gObjHitReactEffectColorArgs;
  if ((reactionState & OBJHITREACT_REACTION_STATE_MASK) != OBJHITREACT_REACTION_STATE_INACTIVE) {
    OSReport(sObjHitReactHitstateFrameString,objAnim->currentMoveProgress);
    moveEnded = ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)
        (obj,(double)*reactionStepScale,(double)timeDelta,(ObjAnimEventList *)0x0);
    if (moveEnded != 0) {
      OSReport(sObjHitReactResetString);
      reactionState = OBJHITREACT_REACTION_STATE_INACTIVE;
    }
  }
  hitType = ObjHits_GetPriorityHitWithPosition(obj,0,&hitSphereIndex,0,&hitPos[0],&hitPos[1],
                                               &hitPos[2]);
  if (hitType != 0) {
    ObjAnimBank *bank = ObjAnim_GetActiveBank(objAnim);
    hitPos[0] = hitPos[0] + playerMapOffsetX;
    hitPos[2] = hitPos[2] + playerMapOffsetZ;
    effectPos.scale = gObjHitsScalarOne;
    effectPos.z = 0;
    effectPos.y = 0;
    effectPos.x = 0;
    animDef = bank->animDef;
    hitSphereIndex = ObjAnim_GetHitReactEntryIndex(animDef,hitSphereIndex);
    if (hitSphereIndex >= (int)(reactionEntryCount & OBJHITREACT_ENTRY_COUNT_MASK)) {
      OSReport(sObjHitReactSphereOverflowString,hitSphereIndex);
      hitSphereIndex = 0;
    }
    reactionEntry = &reactionEntryTable[hitSphereIndex];
    if (hitType != OBJHITREACT_COLLISION_SKIP_REACTION) {
      if ((reactionEntry->primaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)reactionEntry->primaryHitSfxId),
          !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)reactionEntry->primaryHitSfxId);
      }
      if ((reactionEntry->secondaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)reactionEntry->secondaryHitSfxId),
          !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)reactionEntry->secondaryHitSfxId);
      }
      if (reactionEntry->hitEffectMode == OBJHITREACT_HIT_FX_MODE_EFFECT) {
        effectHandle = (ObjHitReactEffectHandle *)
            Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID,OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
        effectHandle->vtable->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE,OBJHITREACT_HIT_EFFECT_MODE,
                                    &effectPos,OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,
                                    OBJHITREACT_HIT_EFFECT_NO_SOURCE,
                                    &effectColorArgs);
        if (effectHandle != (ObjHitReactEffectHandle *)0x0) {
          Resource_Release(effectHandle);
        }
      }
      else {
        objLightFn_8009a1dc(obj,(double)gObjHitReactAltEffectScale,&effectPos,
                            OBJHITREACT_ALT_EFFECT_COUNT,0);
      }
    }
    if (((reactionState & OBJHITREACT_REACTION_STATE_MASK) == OBJHITREACT_REACTION_STATE_INACTIVE) &&
        (reactionEntry->reactionMoveId > OBJHITREACT_NO_REACTION_ANIM)) {
      ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
          (obj,(int)reactionEntry->reactionMoveId,gObjHitsScalarZero,0);
      *reactionStepScale = reactionEntry->reactionStepScale;
      reactionState = OBJHITREACT_REACTION_STATE_ACTIVE;
    }
  }
  return reactionState;
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
  int *objectListCursor;
  int stateActive;
  int resetPending;
  int objectListCount;
  int startIndex;

  objectListCursor = (int *)ObjList_GetObjects(&startIndex,&objectListCount);
  gObjHitReactResetObjectCount = 0;
  while (objectCount > 0) {
    obj = *objectListCursor;
    hitState = ((ObjAnimComponent *)obj)->hitReactState;
    if (hitState != (ObjHitReactState *)0x0) {
      stateActive = hitState->flags & OBJHITREACT_FLAG_ACTIVE;
      if (stateActive != 0) {
        resetPending = hitState->resetFlags & OBJHITREACT_RESET_FLAG_PENDING;
        if (resetPending != 0) {
          if (gObjHitReactResetObjectCount < OBJHITREACT_MAX_RESET_OBJECTS) {
            gObjHitReactResetObjects[gObjHitReactResetObjectCount++] = (ObjAnimComponent *)obj;
          }
          hitState->activeHit = 0;
          hitState->flags = (s16)(hitState->flags & ~OBJHITREACT_FLAG_RESET_PENDING);
          hitState->resetFrameCount = OBJHITREACT_RESET_FRAME_COUNT;
        }
      }
    }
    objectListCursor = objectListCursor + 1;
    objectCount = objectCount + -1;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitbox_AllocRotatedBounds
 * EN v1.0 Address: 0x800356F0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800357E8
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjHitbox_AllocRotatedBounds(ObjHitbox *hitbox,uint arena)
{
  ObjHitboxTransformState *transformState;

  transformState = (ObjHitboxTransformState *)roundUpTo4(arena);
  hitbox->transformState = transformState;
  if (hitbox->transformState != (ObjHitboxTransformState *)0x0) {
    hitbox->transformState->activeMatrixIndex = 0;
    hitbox->transformState->resetFrames = 10;
    hitbox->transformState->contactObjectCount = 0;
    ObjHitbox_UpdateRotatedBounds(hitbox,1);
    ObjHitbox_UpdateRotatedBounds(hitbox,1);
  }
  return (uint)transformState + sizeof(ObjHitboxTransformState);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_LoadMoveEntries
 * EN v1.0 Address: 0x80035774
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8003586C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void ObjHitReact_LoadMoveEntries(ObjAnimComponent *objAnim,ObjAnimBank *bank,int objType,
                                 ObjHitReactState *hitState,int moveId,int async)
{
  ObjHitReactMoveEntry *moveEntry;
  int moveEntryShortOffset;
  s16 entryByteOffset;
  ObjHitReactMoveEntry *moveEntryTable;

  moveEntryTable = objAnim->modelInstance->hitReactMoveTable;
  hitState->activeEntryBytes = 0;
  if (moveEntryTable != (ObjHitReactMoveEntry *)0x0) {
    moveEntryShortOffset = 0;
    for (moveEntry = moveEntryTable; moveEntry->moveId != -1;) {
      if (moveId == moveEntry->moveId) {
        moveEntry = (ObjHitReactMoveEntry *)((s16 *)moveEntryTable + moveEntryShortOffset);
        entryByteOffset = moveEntry->firstEntryByteOffset;
        hitState->activeEntryBytes = moveEntry->entryByteCount;
        if (hitState->activeEntryBytes > hitState->entryByteCapacity) {
          hitState->activeEntryBytes = hitState->entryByteCapacity;
        }
        if (async == 0) {
          getTabEntry(hitState->entries,OBJHITREACT_ENTRY_TAB_FILE_ID,(int)entryByteOffset,
                      (int)hitState->activeEntryBytes);
          return;
        }
        fileLoadToBufferOffset(OBJHITREACT_ENTRY_TAB_FILE_ID,hitState->entries,
                               (int)entryByteOffset,(int)hitState->activeEntryBytes);
        return;
      }
      moveEntry++;
      moveEntryShortOffset += OBJHITREACT_MOVE_ENTRY_SHORT_STRIDE;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHitReact_InitState
 * EN v1.0 Address: 0x80035828
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x80035920
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
uint ObjHitReact_InitState(int objType,ObjAnimBank *bank,ObjHitReactState *hitState,
                           uint entryArena,ObjAnimComponent *objAnim)
{
  ObjHitReactEntry *entries;

  if (bank == (ObjAnimBank *)0x0) {
    return entryArena;
  }
  hitState->entryByteCapacity = OBJHITREACT_ENTRY_ARENA_BYTES;
  entries = (ObjHitReactEntry *)roundUpTo8(entryArena);
  hitState->entries = entries;
  entryArena = (uint)entries + hitState->entryByteCapacity;
  hitState->activeHitboxMode = OBJHITREACT_ACTIVE_HITBOX_MODE;
  if ((hitState->resetFlags & OBJHITREACT_RESET_MODE_MASK) != 0) {
    hitState->resetHitboxMode = OBJHITREACT_RESET_HITBOX_MODE;
  }
  ObjHitReact_LoadMoveEntries(objAnim,bank,objType,hitState,0,1);
  return entryArena;
}
#pragma peephole reset
#pragma scheduling reset
