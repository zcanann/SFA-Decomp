/*
 * hitanimator (DLL 0x0139) - hit-reaction animation driver for map-block
 * objects (HITANIMATOR_CLASS_ID 0x4B). Each instance watches a game bit
 * (HitAnimatorPlacement.gameBit): when the bit's value flips, it toggles
 * state->activeBit and queues the configured reactions via state->flags -
 * a poly toggle (toggleMode), a sound cue (SETUP_FLAG_SOUND) and/or a
 * map-block update (SETUP_FLAG_BLOCK_UPDATE). hitAnimatorFn_80193dbc walks
 * the block's polys and layers to set/clear the visibility/draw bits that
 * realise the reaction.
 *
 * This TU also carries the layout asserts for the wave/alpha/ground/vis
 * animator states it shares headers with.
 */
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
extern void* mapGetBlock(int i);

extern void* fn_8006070C(int* obj, int idx);
extern int fn_80065640(void);
extern void fn_80065574(int matchVal, int obj, int flag);
extern void* mapBlockFn_800606ec(int* obj, int idx);
extern int mapBlockFn_80060678(void* entry);
extern void* Shader_getLayer(char* base, int idx);

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* state,
                            HitAnimatorPlacement* desc);

int hitanimator_getExtraSize(void) { return HITANIMATOR_EXTRA_STATE_BYTES; }

void hitanimator_update(HitAnimatorObject* obj)
{
    HitAnimatorPlacement* desc = (HitAnimatorPlacement*)obj->objAnim.placementData;
    HitAnimatorState* state = obj->state;
    void* block;
    block = mapGetBlock(objPosToMapBlockIdx(
        (double)obj->objAnim.localPosX,
        (double)obj->objAnim.localPosY,
        (double)obj->objAnim.localPosZ));
    if (block == NULL)
    {
        state->flags &= ~HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        return;
    }
    state->gameBitValue = GameBit_Get(desc->gameBit);
    if (state->previousGameBitValue != state->gameBitValue)
    {
        state->activeBit = state->activeBit ^ 1;
        if (desc->toggleMode == 1)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
        if ((desc->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        }
    }
    state->previousGameBitValue = state->gameBitValue;
    if ((desc->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0)
    {
        if (fn_80065640() != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((state->flags & HITANIMATOR_STATE_FLAG_SOUND_PENDING) != 0)
        {
            if (fn_80065640() == 0)
            {
                fn_80065574(desc->soundId, (int)obj->objAnim.parent, state->activeBit);
                state->flags &= ~HITANIMATOR_STATE_FLAG_SOUND_PENDING;
            }
        }
    }
    if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
    {
        if (desc->blockEffectId != 0)
        {
            if ((state->flags & HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING) != 0)
            {
                hitAnimatorFn_80193dbc(block, obj, state, desc);
                state->flags &= ~HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
            }
        }
    }
}

void hitanimator_init(HitAnimatorObject* obj, HitAnimatorPlacement* desc)
{
    HitAnimatorState* state = obj->state;
    void* block;
    u8 gameBitValue;
    s8 initialBit;
    initialBit = (s8)(desc->flags & HITANIMATOR_SETUP_FLAG_INITIAL_INVERT);
    state->activeBit = initialBit;
    state->flags = 0;
    if (GameBit_Get(desc->gameBit) != 0)
    {
        state->activeBit = state->activeBit ^ 1;
        if (desc->toggleMode == 1)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
    }
    block = mapGetBlock(objPosToMapBlockIdx(
        (double)obj->objAnim.localPosX,
        (double)obj->objAnim.localPosY,
        (double)obj->objAnim.localPosZ));
    if (block != NULL)
    {
        if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0 && desc->blockEffectId != 0)
        {
            hitAnimatorFn_80193dbc(block, obj, state, desc);
        }
    }
    state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
    if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
    {
        state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
    }
    gameBitValue = GameBit_Get(desc->gameBit);
    state->gameBitValue = gameBitValue;
    state->previousGameBitValue = gameBitValue;
    obj->objectFlags |= HITANIMATOR_OBJECT_FLAGS_ENABLED;
}

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* state, HitAnimatorPlacement* desc)
{
    int i;
    char* poly;

    if ((desc->flags & HITANIMATOR_SETUP_FLAG_SKIP_POLYS) == 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->unk9A; i++)
        {
            poly = mapBlockFn_800606ec(block, i);
            if (desc->blockEffectId == mapBlockFn_80060678(poly))
            {
                if (state->activeBit != 0)
                {
                    *(u32*)(poly + 0x10) &= ~2LL;
                    if ((desc->flags & HITANIMATOR_SETUP_FLAG_AFFECT_SHADERS) != 0)
                    {
                        *(u32*)(poly + 0x10) &= ~1LL;
                    }
                }
                else
                {
                    *(int*)(poly + 0x10) |= 2;
                    if ((desc->flags & HITANIMATOR_SETUP_FLAG_AFFECT_SHADERS) != 0)
                    {
                        *(int*)(poly + 0x10) |= 1;
                    }
                }
            }
        }
    }
    if ((desc->flags & HITANIMATOR_SETUP_FLAG_AFFECT_SHADERS) != 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->unkA2; i++)
        {
            char* shader = fn_8006070C(block, i);
            u8* layer = Shader_getLayer(shader, 0);
            if (desc->blockEffectId == layer[5])
            {
                if (state->activeBit != 0)
                {
                    *(u32*)(shader + 0x3c) &= ~2LL;
                }
                else
                {
                    *(int*)(shader + 0x3c) |= 2;
                }
            }
        }
    }
}
