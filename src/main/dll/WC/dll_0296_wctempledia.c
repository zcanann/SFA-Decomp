/*
 * wctempledia (DLL 0x296) - a rotating temple dial puzzle in the Walled
 * City (WC). The dial spins about Z, easing currentSpeed toward
 * targetSpeed, and drives a looped roar sfx whose volume/pitch track the
 * spin ratio. It is a 3-stage ordered lock: each stage's game bit must
 * light in order, and setting a later stage while an earlier one is unset
 * clears all three bits, plays the reset sfx and drops back to the base
 * speed. Clearing the stages in order steps targetSpeed up through the
 * table. Solving all three sets the placement solvedBit, latches
 * FLAG_SOLVED and freezes the dial. Two model variants select distinct
 * game-bit/target-table pairs at init; syncPartVisibility toggles per-stage
 * texture overrides to reveal solved segments.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

#define WCTEMPLE_DIA_EXTRA_SIZE 0x14
#define WCTEMPLE_DIA_STAGE_COUNT 3
#define WCTEMPLE_DIA_ALL_STAGES_MASK 7
#define WCTEMPLE_DIA_VISIBLE_OVERRIDE 0x100

#define WCTEMPLE_DIA_SETUP_TYPE_OFFSET 0x18
#define WCTEMPLE_DIA_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCTEMPLE_DIA_SETUP_SOLVED_BIT_OFFSET 0x1e

#define WCTEMPLE_DIA_STATE_CURRENT_SPEED 0x00
#define WCTEMPLE_DIA_STATE_TARGET_SPEED 0x04
#define WCTEMPLE_DIA_STATE_STAGE_MASK 0x08
#define WCTEMPLE_DIA_STATE_FLAGS 0x09
#define WCTEMPLE_DIA_STATE_TARGET_TABLE 0x0c
#define WCTEMPLE_DIA_STATE_GAMEBITS 0x10

#define WCTEMPLE_DIA_FLAG_SOLVED 1

#define WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG 2

#define WCTEMPLE_DIA_RESET_SFX 0x487
#define WCTEMPLE_DIA_STAGE_SFX 0x409

typedef struct WCTempleDiaSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[WCTEMPLE_DIA_SETUP_SOLVED_BIT_OFFSET - 0x1A];
    s16 solvedBit;
    u8 pad20[0x24 - 0x20];
} WCTempleDiaSetup;

typedef struct WCTempleDiaState
{
    f32 currentSpeed;
    f32 targetSpeed;
    u8 stageMask;
    u8 flags;
    u8 pad0A[WCTEMPLE_DIA_STATE_TARGET_TABLE - 0x0A];
    f32* targetTable;
    s16* gamebits;
} WCTempleDiaState;

STATIC_ASSERT(sizeof(WCTempleDiaState) == WCTEMPLE_DIA_EXTRA_SIZE);
STATIC_ASSERT(sizeof(WCTempleDiaSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTempleDiaState, currentSpeed) == WCTEMPLE_DIA_STATE_CURRENT_SPEED);
STATIC_ASSERT(offsetof(WCTempleDiaState, targetSpeed) == WCTEMPLE_DIA_STATE_TARGET_SPEED);
STATIC_ASSERT(offsetof(WCTempleDiaState, stageMask) == WCTEMPLE_DIA_STATE_STAGE_MASK);
STATIC_ASSERT(offsetof(WCTempleDiaState, flags) == WCTEMPLE_DIA_STATE_FLAGS);
STATIC_ASSERT(offsetof(WCTempleDiaState, targetTable) == WCTEMPLE_DIA_STATE_TARGET_TABLE);
STATIC_ASSERT(offsetof(WCTempleDiaState, gamebits) == WCTEMPLE_DIA_STATE_GAMEBITS);
STATIC_ASSERT(offsetof(WCTempleDiaSetup, type) == WCTEMPLE_DIA_SETUP_TYPE_OFFSET);
STATIC_ASSERT(offsetof(WCTempleDiaSetup, modelIndex) == WCTEMPLE_DIA_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCTempleDiaSetup, solvedBit) == WCTEMPLE_DIA_SETUP_SOLVED_BIT_OFFSET);

void wctempledia_syncPartVisibility(int obj, u8 mask)
{
    int bit;
    int part;
    int block;
    int slot;

    block = (int)mapGetBlock(objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                            ((GameObject*)obj)->anim.localPosZ));
    if ((void*)block != NULL)
    {
        for (part = 1; part < WCTEMPLE_DIA_STAGE_COUNT + 1; part++)
        {
            slot = 0;
            bit = mask & (1 << (part - 1));
            for (; slot < *(u8*)(block + 0xa2); slot++)
            {
                int entry = fn_8006070C(block, slot);
                if (*(u8*)(entry + 0x29) == part)
                {
                    if (bit != 0)
                    {
                        mapTextureOverrideSetValue(part, *(int*)(entry + 0x24), WCTEMPLE_DIA_VISIBLE_OVERRIDE);
                    }
                    else
                    {
                        mapTextureOverrideSetValue(part, *(int*)(entry + 0x24), 0);
                    }
                }
            }
        }
    }
}

int wctempledia_interactCallback(int obj, int p2, ObjAnimUpdateState* animUpdate)
{
    WCTempleDiaState* state = ((GameObject*)obj)->extra;

    {
        f32 cs;
        f32 scaled = lbl_803E6E48 * -(cs = state->currentSpeed);
        state->currentSpeed = scaled * timeDelta + cs;
    }
    ((GameObject*)obj)->anim.rotZ = (s16)(timeDelta * state->currentSpeed + (f32)((GameObject*)obj)->anim.rotZ);
    animUpdate->sequenceEventActive = 0;
    animUpdate->activeHitVolumePair &= ~WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG;
    animUpdate->hitVolumePair &= ~WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG;
    return 0;
}

int wctempledia_getExtraSize(void) { return WCTEMPLE_DIA_EXTRA_SIZE; }

int wctempledia_getObjectTypeId(void) { return 0; }

void wctempledia_free(void)
{
}

void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E58);
    }
}

void wctempledia_hitDetect(void)
{
}

void wctempledia_update(int obj)
{
    WCTempleDiaSetup* setup = (WCTempleDiaSetup*)((GameObject*)obj)->anim.placementData;
    WCTempleDiaState* state = ((GameObject*)obj)->extra;
    int stage;
    int priorStage;
    int resetStage;

    if (state->flags & WCTEMPLE_DIA_FLAG_SOLVED)
    {
        wctempledia_syncPartVisibility(obj, state->stageMask);
        return;
    }
    state->currentSpeed += timeDelta * (lbl_803E6E48 * (state->targetSpeed - state->currentSpeed));
    ((GameObject*)obj)->anim.rotZ = (s16)(timeDelta * state->currentSpeed + (f32)((GameObject*)obj)->anim.rotZ);
    Sfx_KeepAliveLoopedObjectSound(obj, SFXmn_sml_trex_roar);
    {
        f32 ratio = state->currentSpeed / state->targetTable[2];
        u8 vol = (u8)(int)(lbl_803E6E60 * ratio + lbl_803E6E5C);
        Sfx_SetObjectSfxVolume(obj, SFXmn_sml_trex_roar, vol,
                               lbl_803E6E68 * ratio + lbl_803E6E64);
    }
    for (stage = 0; stage < WCTEMPLE_DIA_STAGE_COUNT; stage++)
    {
        int bit = 1 << stage;
        if ((state->stageMask & bit) == 0 &&
            GameBit_Get(state->gamebits[stage]) != 0)
        {
            int found = 0;
            for (priorStage = 0; priorStage < stage; priorStage++)
            {
                if ((state->stageMask & (1 << priorStage)) == 0)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                for (resetStage = 0; resetStage < WCTEMPLE_DIA_STAGE_COUNT; resetStage++)
                {
                    GameBit_Set(state->gamebits[resetStage], 0);
                }
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_RESET_SFX);
                state->stageMask = 0;
                state->targetSpeed = state->targetTable[0];
                break;
            }
            state->stageMask |= bit;
            if (stage == 0)
            {
                state->targetSpeed = state->targetTable[1];
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_STAGE_SFX);
            }
            else if (stage == 1)
            {
                state->targetSpeed = state->targetTable[2];
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_STAGE_SFX);
            }
        }
    }
    wctempledia_syncPartVisibility(obj, state->stageMask);
    if (state->stageMask == WCTEMPLE_DIA_ALL_STAGES_MASK)
    {
        GameBit_Set(setup->solvedBit, 1);
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
        state->flags |= WCTEMPLE_DIA_FLAG_SOLVED;
    }
}

void wctempledia_init(int obj, int setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCTempleDiaState* state = ((GameObject*)obj)->extra;
    WCTempleDiaSetup* setupData = (WCTempleDiaSetup*)setup;
    int i;

    ((GameObject*)obj)->anim.rotX = (s16)(setupData->type << 8);
    *(u8*)&objAnim->bankIndex = setupData->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    if (objAnim->bankIndex == 0)
    {
        state->gamebits = &lbl_803DC3B8;
        state->targetTable = lbl_8032B348;
    }
    else
    {
        state->gamebits = &lbl_803DC3C0;
        state->targetTable = lbl_8032B354;
    }
    for (i = 0; i < WCTEMPLE_DIA_STAGE_COUNT; i++)
    {
        if ((u32)GameBit_Get(state->gamebits[i]) != 0)
        {
            state->stageMask |= (1 << i);
        }
    }
    if ((u32)GameBit_Get(setupData->solvedBit) != 0)
    {
        state->stageMask = WCTEMPLE_DIA_ALL_STAGES_MASK;
        state->flags |= WCTEMPLE_DIA_FLAG_SOLVED;
    }
    if (state->stageMask & 2)
    {
        state->currentSpeed = state->targetTable[2];
    }
    else if (state->stageMask & 1)
    {
        state->currentSpeed = state->targetTable[1];
    }
    else
    {
        state->currentSpeed = state->targetTable[0];
    }
    state->targetSpeed = state->currentSpeed;
    ((GameObject*)obj)->animEventCallback = (void*)wctempledia_interactCallback;
    wctempledia_syncPartVisibility(obj, state->stageMask);
}

void wctempledia_release(void)
{
}

void wctempledia_initialise(void)
{
}
