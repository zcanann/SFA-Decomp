#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objlib.h"

extern int Sfx_IsPlayingFromObject(int obj,u16 sfxId);
extern void Sfx_PlayFromObject(int obj,u16 sfxId);
extern void Resource_Release(void *handle);
extern void objLightFn_8009a1dc(int obj,double scale,undefined2 *pos,u32 count,int *param_5);
extern uint roundUpTo4(uint value);
extern uint roundUpTo8(uint value);
extern void getTabEntry(void *dst,int fileId,int offset,int size);
extern void fileLoadToBufferOffset(int fileId,void *dst,int offset,int size);

extern ObjHitReactEffectColorArgs gObjHitReactEffectColorArgs;
extern char sObjHitReactHitstateFrameString[];
extern char sObjHitReactSphereOverflowString[];
extern char sObjHitReactResetString[7];
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 gObjHitsScalarZero;
extern f32 gObjHitsScalarOne;
extern f32 gObjHitReactAltEffectScale;
extern int gObjHitReactResetObjectCount;
extern ObjAnimComponent **gObjHitReactResetObjects;

extern ObjHitReactEffectHandle *Resource_Acquire(u32 effectId,u32 count);

/*
 * --INFO--
 *
 * Function: ObjHitReact_Update
 * EN v1.0 Address: 0x800353A4
 * EN v1.0 Size: 652b
 */
#pragma scheduling off
#pragma peephole off
int ObjHitReact_Update(int obj,ObjHitReactEntry *reactionEntries,u32 reactionEntryCount,
                       u32 reactionState,float *reactionStepScale)
{
  ObjAnimDef *animDef;
  int moveEnded;
  int priorityHitType;
  ObjHitReactEffectHandle *effectHandle;
  bool sfxActive;
  f32 hitPos[3];
  ObjHitReactEffectPos effectPos;
  ObjHitReactEffectColorArgs effectColorArgs;
  int hitSphereIndex;

  effectColorArgs = gObjHitReactEffectColorArgs;
  if ((reactionState & OBJHITREACT_REACTION_STATE_MASK) != OBJHITREACT_REACTION_STATE_INACTIVE) {
    OSReport(sObjHitReactHitstateFrameString,((ObjAnimComponent *)obj)->currentMoveProgress);
    moveEnded = ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)
        (obj,(double)*reactionStepScale,(double)timeDelta,(ObjAnimEventList *)0x0);
    if (moveEnded != 0) {
      OSReport(sObjHitReactResetString);
      reactionState = OBJHITREACT_REACTION_STATE_INACTIVE;
    }
  }
  priorityHitType = ObjHits_GetPriorityHitWithPosition(obj,0,&hitSphereIndex,0,&hitPos[0],
                                                       &hitPos[1],&hitPos[2]);
  if (priorityHitType != 0) {
    ObjAnimBank *bank = ObjAnim_GetActiveBank((ObjAnimComponent *)obj);
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
    reactionEntries = &reactionEntries[hitSphereIndex];
    if (priorityHitType != OBJHITREACT_COLLISION_SKIP_REACTION) {
      if ((reactionEntries->primaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)reactionEntries->primaryHitSfxId),
          !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)reactionEntries->primaryHitSfxId);
      }
      if ((reactionEntries->secondaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
          (sfxActive = Sfx_IsPlayingFromObject(obj,(u16)reactionEntries->secondaryHitSfxId),
          !sfxActive)) {
        Sfx_PlayFromObject(obj,(u16)reactionEntries->secondaryHitSfxId);
      }
      if (reactionEntries->hitEffectMode == OBJHITREACT_HIT_FX_MODE_EFFECT) {
        effectHandle =
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
        objLightFn_8009a1dc(obj,(double)gObjHitReactAltEffectScale,(undefined2 *)&effectPos.x,
                            OBJHITREACT_ALT_EFFECT_COUNT,0);
      }
    }
    if (((reactionState & OBJHITREACT_REACTION_STATE_MASK) == OBJHITREACT_REACTION_STATE_INACTIVE) &&
        (reactionEntries->reactionMoveId > OBJHITREACT_NO_REACTION_ANIM)) {
      ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
          (obj,(int)reactionEntries->reactionMoveId,gObjHitsScalarZero,0);
      *reactionStepScale = reactionEntries->reactionStepScale;
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
  int *objectList;
  int stateActive;
  int resetPending;
  int objectListCount;
  int startIndex;

  objectList = (int *)ObjList_GetObjects(&startIndex,&objectListCount);
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
            gObjHitReactResetObjects[gObjHitReactResetObjectCount++] = (ObjAnimComponent *)obj;
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
  s16 firstEntryByteOffset;
  ObjHitReactMoveEntry *moveEntryTable;

  moveEntryTable = objAnim->modelInstance->hitReactMoveTable;
  hitState->activeEntryBytes = 0;
  if (moveEntryTable != (ObjHitReactMoveEntry *)0x0) {
    moveEntryShortOffset = 0;
    for (moveEntry = moveEntryTable; moveEntry->moveId != -1;) {
      if (moveId == moveEntry->moveId) {
        moveEntry = (ObjHitReactMoveEntry *)((s16 *)moveEntryTable + moveEntryShortOffset);
        firstEntryByteOffset = moveEntry->firstEntryByteOffset;
        hitState->activeEntryBytes = moveEntry->entryByteCount;
        if (hitState->activeEntryBytes > hitState->entryByteCapacity) {
          hitState->activeEntryBytes = hitState->entryByteCapacity;
        }
        if (async == 0) {
          getTabEntry(hitState->entries,OBJHITREACT_ENTRY_TAB_FILE_ID,(int)firstEntryByteOffset,
                      (int)hitState->activeEntryBytes);
          return;
        }
        fileLoadToBufferOffset(OBJHITREACT_ENTRY_TAB_FILE_ID,hitState->entries,
                               (int)firstEntryByteOffset,(int)hitState->activeEntryBytes);
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
