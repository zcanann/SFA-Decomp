#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objlib.h"
#include "main/resource.h"

extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

int ObjHitReact_Update(int obj, ObjHitReactEntry* reactionEntryTable, u32 reactionEntryCount,
                       u32 reactionState, float* reactionStepScale)
{
    ObjAnimDef* animDef;
    ObjAnimComponent* objAnim;
    int moveEnded;
    int hitType;
    ObjHitReactEntry* reactionEntry;
    ObjHitReactEffectHandle* effectHandle;
    bool sfxActive;
    f32 hitPos[3];
    ObjHitReactEffectPos effectPos;
    ObjHitReactEffectColorArgs effectColorArgs;
    int hitSphereIndex;

    objAnim = (ObjAnimComponent*)obj;
    effectColorArgs = gObjHitReactEffectColorArgs;
    if ((reactionState & OBJHITREACT_REACTION_STATE_MASK) != OBJHITREACT_REACTION_STATE_INACTIVE)
    {
        OSReport(sObjHitReactHitstateFrameString, objAnim->currentMoveProgress);
        moveEnded = ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)
            (obj, (double)*reactionStepScale, (double)timeDelta, NULL);
        if (moveEnded != 0)
        {
            OSReport(sObjHitReactResetString);
            reactionState = OBJHITREACT_REACTION_STATE_INACTIVE;
        }
    }
    hitType = ObjHits_GetPriorityHitWithPosition(obj, 0, &hitSphereIndex, 0, &hitPos[0], &hitPos[1],
                                                 &hitPos[2]);
    if (hitType != 0)
    {
        ObjAnimBank* bank = ObjAnim_GetActiveBank(objAnim);
        hitPos[0] = hitPos[0] + playerMapOffsetX;
        hitPos[2] = hitPos[2] + playerMapOffsetZ;
        effectPos.scale = gObjHitsScalarOne;
        effectPos.z = 0;
        effectPos.y = 0;
        effectPos.x = 0;
        animDef = bank->animDef;
        hitSphereIndex = ObjAnim_GetHitReactEntryIndex(animDef, hitSphereIndex);
        if (hitSphereIndex >= (int)(reactionEntryCount & OBJHITREACT_ENTRY_COUNT_MASK))
        {
            OSReport(sObjHitReactSphereOverflowString, hitSphereIndex);
            hitSphereIndex = 0;
        }
        reactionEntry = &reactionEntryTable[hitSphereIndex];
        if (hitType != OBJHITREACT_COLLISION_SKIP_REACTION)
        {
            if ((reactionEntry->primaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
                (sfxActive = Sfx_IsPlayingFromObject(obj, (u16)reactionEntry->primaryHitSfxId),
                    !sfxActive))
            {
                Sfx_PlayFromObject(obj, reactionEntry->primaryHitSfxId);
            }
            if ((reactionEntry->secondaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
                (sfxActive = Sfx_IsPlayingFromObject(obj, (u16)reactionEntry->secondaryHitSfxId),
                    !sfxActive))
            {
                Sfx_PlayFromObject(obj, reactionEntry->secondaryHitSfxId);
            }
            if (reactionEntry->hitEffectMode == OBJHITREACT_HIT_FX_MODE_EFFECT)
            {
                effectHandle = (ObjHitReactEffectHandle*)
                    Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID, OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
                effectHandle->vtable->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE,
                                            &effectPos, OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS,
                                            OBJHITREACT_HIT_EFFECT_NO_SOURCE,
                                            &effectColorArgs);
                if (effectHandle != (ObjHitReactEffectHandle*)0x0)
                {
                    Resource_Release(effectHandle);
                }
            }
            else
            {
                objLightFn_8009a1dc((void*)obj, gObjHitReactAltEffectScale, &effectPos,
                                    OBJHITREACT_ALT_EFFECT_COUNT, NULL);
            }
        }
        if (((reactionState & OBJHITREACT_REACTION_STATE_MASK) == OBJHITREACT_REACTION_STATE_INACTIVE) &&
            (reactionEntry->reactionMoveId > OBJHITREACT_NO_REACTION_ANIM))
        {
            ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                (obj, reactionEntry->reactionMoveId, gObjHitsScalarZero, 0);
            *reactionStepScale = reactionEntry->reactionStepScale;
            reactionState = OBJHITREACT_REACTION_STATE_ACTIVE;
        }
    }
    return reactionState;
}

void ObjHitReact_ResetActiveObjects(int objectCount)
{
    ObjHitReactState* hitState;
    ObjAnimComponent* objAnim;
    ObjAnimComponent** objectListCursor;
    int stateActive;
    int resetPending;
    int objectListCount;
    int startIndex;

    objectListCursor = (ObjAnimComponent**)ObjList_GetObjects(&startIndex, &objectListCount);
    gObjHitReactResetObjectCount = 0;
    while (objectCount > 0)
    {
        objAnim = *objectListCursor;
        hitState = objAnim->hitReactState;
        if (hitState != NULL)
        {
            stateActive = hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED;
            if (stateActive != 0)
            {
                resetPending = hitState->shapeFlags & OBJHITREACT_SHAPE_RESET_UPDATE;
                if (resetPending != 0)
                {
                    if (gObjHitReactResetObjectCount < OBJHITREACT_MAX_RESET_OBJECTS)
                    {
                        gObjHitReactResetObjects[gObjHitReactResetObjectCount++] = objAnim;
                    }
                    hitState->activeHit = 0;
                    hitState->flags = (s16)(hitState->flags & ~OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED);
                    hitState->resetFrameCount = OBJHITREACT_RESET_FRAME_COUNT;
                }
            }
        }
        objectListCursor = objectListCursor + 1;
        objectCount = objectCount + -1;
    }
}

int ObjHitbox_AllocRotatedBounds(ObjHitbox* hitbox, u32 arena)
{
    ObjHitboxTransformState* transformState;

    transformState = (ObjHitboxTransformState*)roundUpTo4(arena);
    hitbox->transformState = transformState;
    if (hitbox->transformState != NULL)
    {
        hitbox->transformState->activeMatrixIndex = 0;
        hitbox->transformState->resetFrames = OBJHITBOX_ROTATED_BOUNDS_RESET_FRAMES;
        hitbox->transformState->contactObjectCount = 0;
        ObjHitbox_UpdateRotatedBounds(hitbox, 1);
        ObjHitbox_UpdateRotatedBounds(hitbox, 1);
    }
    return (u32)transformState + sizeof(ObjHitboxTransformState);
}

#pragma dont_inline on
void ObjHitReact_LoadMoveEntries(ObjAnimComponent* objAnim, ObjAnimBank* bank, int objType,
                                 ObjHitReactState* hitState, int moveId, int async)
{
    int moveEntryWordIndex;
    s16* moveEntryTable;
    s16* moveEntry;
    s16 entryByteOffset;

    moveEntryTable = (s16*)objAnim->modelInstance->hitReactMoveTable;
    hitState->activeEntryByteCount = 0;
    if (moveEntryTable != NULL)
    {
        for (moveEntryWordIndex = 0, moveEntry = moveEntryTable; moveEntry[0] != OBJHITREACT_MOVE_ID_END;
             moveEntry += OBJHITREACT_MOVE_ENTRY_SHORT_COUNT, moveEntryWordIndex += OBJHITREACT_MOVE_ENTRY_SHORT_COUNT)
        {
            if (moveId == moveEntry[0])
            {
                moveEntry = &moveEntryTable[moveEntryWordIndex];
                entryByteOffset = moveEntry[1];
                hitState->activeEntryByteCount = moveEntry[2];
                if (hitState->activeEntryByteCount > hitState->entryBufferByteCapacity)
                {
                    hitState->activeEntryByteCount = hitState->entryBufferByteCapacity;
                }
                if (async == 0)
                {
                    getTabEntry(hitState->entries, OBJHITREACT_ENTRY_TAB_FILE_ID, entryByteOffset,
                                hitState->activeEntryByteCount);
                    return;
                }
                fileLoadToBufferOffset(OBJHITREACT_ENTRY_TAB_FILE_ID, hitState->entries,
                                       entryByteOffset, hitState->activeEntryByteCount);
                return;
            }
        }
    }
    return;
}
#pragma dont_inline reset

u32 ObjHitReact_InitState(int objType, ObjAnimBank* bank, ObjHitReactState* hitState,
                          u32 entryArena, ObjAnimComponent* objAnim)
{
    ObjHitReactEntry* entries;

    if (bank == NULL)
    {
        return entryArena;
    }
    hitState->entryBufferByteCapacity = OBJHITREACT_ENTRY_ARENA_BYTES;
    entries = (ObjHitReactEntry*)roundUpTo8(entryArena);
    hitState->entries = entries;
    entryArena = (u32)entries + hitState->entryBufferByteCapacity;
    hitState->activeHitboxMode = OBJHITREACT_ACTIVE_HITBOX_MODE;
    if ((hitState->shapeFlags & OBJHITS_SHAPE_RESET_MODE_MASK) != 0)
    {
        hitState->resetHitboxMode = OBJHITREACT_RESET_HITBOX_MODE;
    }
    ObjHitReact_LoadMoveEntries(objAnim, bank, objType, hitState, 0, 1);
    return entryArena;
}

char sObjHitReactHitstateFrameString[] = "hitstate frame=%f\n";
char sObjHitReactSphereOverflowString[] = "objHitReact.c: sphere overflow! %d\n";
