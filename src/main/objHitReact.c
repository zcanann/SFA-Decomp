#include "dolphin/os.h"
#include "main/shader_api.h"
#include "main/game_object.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objHitReact_types.h"
#include "main/dll/dll_005A_staffcollisionfunc03.h"
#include "main/objhits.h"
#include "main/obj_list.h"
#include "main/resource.h"
#include "main/frame_timing.h"

f32 lbl_803DB450 = 0.4f;
char sObjHitReactResetString[7] = "reset\n";


const StaffCollisionColorArgs gObjHitReactEffectColorArgs = {8, 0xB4, 0xF0, 0xFF};

u32 ObjHitReact_Update(int obj, ObjHitReactEntry* reactionEntryTable, u32 reactionEntryCount, u32 reactionState,
                      float* reactionStepScale)
{
    ObjAnimDef* animDef;
    ObjAnimComponent* objAnim;
    int moveEnded;
    int hitType;
    ObjHitReactEntry* reactionEntry;
    StaffCollisionInterface** effectResource;
    bool sfxActive;
    PartFxSpawnParams effectParams;
    StaffCollisionColorArgs effectColorArgs;
    int hitSphereIndex;

    objAnim = (ObjAnimComponent*)obj;
    effectColorArgs = gObjHitReactEffectColorArgs;
    if ((reactionState & OBJHITREACT_REACTION_STATE_MASK) != OBJHITREACT_REACTION_STATE_INACTIVE)
    {
        OSReport(sObjHitReactHitstateFrameString, objAnim->currentMoveProgress);
        moveEnded = ObjAnim_AdvanceCurrentMove((int)obj, (double)*reactionStepScale,
                                                                              (double)timeDelta, NULL);
        if (moveEnded != 0)
        {
            OSReport(sObjHitReactResetString);
            reactionState = OBJHITREACT_REACTION_STATE_INACTIVE;
        }
    }
    hitType = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), 0, &hitSphereIndex, 0, &effectParams.posX,
                                                 &effectParams.posY, &effectParams.posZ);
    if (hitType != 0)
    {
        ObjAnimBank* bank = ObjAnim_GetActiveBank(objAnim);
        effectParams.posX = effectParams.posX + playerMapOffsetX;
        effectParams.posZ = effectParams.posZ + playerMapOffsetZ;
        effectParams.scale = gObjHitsScalarOne;
        effectParams.rotZ = 0;
        effectParams.rotY = 0;
        effectParams.rotX = 0;
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
                (sfxActive = Sfx_IsPlayingFromObject(obj, (u16)reactionEntry->primaryHitSfxId), !sfxActive))
            {
                Sfx_PlayFromObject(obj, reactionEntry->primaryHitSfxId);
            }
            if ((reactionEntry->secondaryHitSfxId > OBJHITREACT_NO_SFX_ID) &&
                (sfxActive = Sfx_IsPlayingFromObject(obj, (u16)reactionEntry->secondaryHitSfxId), !sfxActive))
            {
                Sfx_PlayFromObject(obj, reactionEntry->secondaryHitSfxId);
            }
            if (reactionEntry->hitEffectMode == OBJHITREACT_HIT_FX_MODE_EFFECT)
            {
                effectResource = Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID, OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
                (*effectResource)
                    ->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE, &effectParams,
                            OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS, OBJHITREACT_HIT_EFFECT_NO_SOURCE, &effectColorArgs);
                if (effectResource != NULL)
                {
                    Resource_Release(effectResource);
                }
            }
            else
            {
                objLightFn_8009a1dc((void*)obj, gObjHitReactAltEffectScale, &effectParams, OBJHITREACT_ALT_EFFECT_COUNT,
                                    NULL);
            }
        }
        if (((reactionState & OBJHITREACT_REACTION_STATE_MASK) == OBJHITREACT_REACTION_STATE_INACTIVE) &&
            (reactionEntry->reactionMoveId > OBJHITREACT_NO_REACTION_ANIM))
        {
            ObjAnim_SetCurrentMove(obj, reactionEntry->reactionMoveId, gObjHitsScalarZero, 0);
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

void ObjHitReact_LoadMoveEntries(ObjAnimComponent* objAnim, ObjAnimBank* bank, int objType, ObjHitReactState* hitState,
                                 int moveId, int async)
{
    int moveEntryWordIndex;
    s16* moveEntryTable;
    s16* moveEntry;
    s16 entryByteOffset;

    moveEntryTable = (s16*)objAnim->modelInstance->hitReactMoveTable;
    hitState->activeEntryByteCount = 0;
    if (moveEntryTable != NULL)
    {
        for (moveEntryWordIndex = 0, moveEntry = moveEntryTable;
             ((ObjHitReactMoveEntry*)moveEntry)->moveId != OBJHITREACT_MOVE_ID_END;
             moveEntry += OBJHITREACT_MOVE_ENTRY_SHORT_COUNT, moveEntryWordIndex += OBJHITREACT_MOVE_ENTRY_SHORT_COUNT)
        {
            if (moveId == ((ObjHitReactMoveEntry*)moveEntry)->moveId)
            {
                moveEntry = &moveEntryTable[moveEntryWordIndex];
                entryByteOffset = ((ObjHitReactMoveEntry*)moveEntry)->firstEntryByteOffset;
                hitState->activeEntryByteCount = ((ObjHitReactMoveEntry*)moveEntry)->entryByteCount;
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
                fileLoadToBufferOffset(OBJHITREACT_ENTRY_TAB_FILE_ID, hitState->entries, entryByteOffset,
                                       hitState->activeEntryByteCount);
                return;
            }
        }
    }
    return;
}

u32 ObjHitReact_InitState(int objType, ObjAnimBank* bank, ObjHitReactState* hitState, u32 entryArena,
                          ObjAnimComponent* objAnim)
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
