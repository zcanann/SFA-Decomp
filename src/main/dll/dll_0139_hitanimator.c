/*
 * hitanimator (DLL 0x0139) - hit-reaction animation driver for map-block
 * objects (HITANIMATOR_CLASS_ID 0x4B). Each instance watches a game bit
 * (HitAnimatorPlacement.gameBit): when the bit's value flips, it toggles
 * state->activeBit and queues the configured reactions via state->flags -
 * a poly toggle (toggleMode), a sound cue (SETUP_FLAG_SOUND) and/or a
 * map-block update (SETUP_FLAG_BLOCK_UPDATE). hitAnimatorFn_80193dbc walks
 * the block's polys and layers to set/clear the visibility/draw bits that
 * realise the reaction. FUN_80192488 is the sibling texture-scroll context
 * pass that recolours the block's texture cells, gated on the two map ids
 * TEXSCROLL_GAMEBIT_GATED_MAP_A/B.
 *
 * This TU also carries the layout asserts for the wave/alpha/ground/vis
 * animator states it shares headers with.
 */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"

extern u32 GameBit_Get(u32 bit);
extern u8* mapGetBlock(int idx);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern char* fn_8006070C(void* block, int idx);

extern int FUN_80017af0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();

extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern void* mapBlockFn_800606ec(void* block, int idx);
extern int mapBlockFn_80060678(void* entry);
extern u8* Shader_getLayer(char* s, int layer);

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

/* on-state wraps FUN_80192488 + hitanimator_getExtraSize (off-pair restores it below) */
#pragma scheduling on
#pragma peephole on
extern void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* state,
                                   HitAnimatorPlacement* desc);

/* BANKED PARTIAL: raw Ghidra output (undefined types, FUN_ callees, offset derefs) - unprocessed */
void FUN_80192488(void)
{
    int texV;
    int ctxHi;
    int block;
    int polyIdx;
    int cell;
    uint gameBit;
    int texU;
    int ctxLo;
    int mapId;
    int placement;
    int vtxIdx;
    int vtx;
    undefined8 pair;

    pair = FUN_8028682c();
    ctxHi = (int)((ulonglong)pair >> 0x20);
    ctxLo = (int)pair;
    placement = *(int*)(ctxHi + 0x4c);
    block = FUN_8005b398((double)*(float*)(ctxHi + 0xc), (double)*(float*)(ctxHi + 0x10));
    block = FUN_8005af70(block);
    if (block == 0)
    {
        *(undefined*)(ctxLo + 0x10) = 1;
    }
    else
    {
        polyIdx = FUN_80017af0(0xe);
        if ((polyIdx != 0) &&
            (placement = FUN_8005337c(-*(int*)(polyIdx + *(short*)(placement + 0x18) * 4)), placement != 0))
        {
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx++)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx++)
                {
                    if (*(int*)(vtx + 0x24) == placement)
                    {
                        texU = (uint) * (ushort*)(placement + 10) << 6;
                        texV = (uint) * (ushort*)(placement + 0xc) << 6;
                        if (*(byte*)(vtx + 0x2a) == 0xff)
                        {
                            texU = FUN_80056448((int)*(char*)(ctxLo + 0x11), (int)*(char*)(ctxLo + 0x12), texU,
                                                 texV);
                            *(char*)(vtx + 0x2a) = (char)texU;
                        }
                        else
                        {
                            mapId = *(int*)(*(int*)(ctxHi + 0x4c) + 0x14);
                            if ((mapId == TEXSCROLL_GAMEBIT_GATED_MAP_A) || (mapId == TEXSCROLL_GAMEBIT_GATED_MAP_B))
                            {
                                gameBit = GameBit_Get(*(uint*)(ctxLo + 8));
                                if (gameBit != 0)
                                {
                                    FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                                 (int)*(char*)(ctxLo + 0x12), texU, texV);
                                }
                            }
                            else
                            {
                                FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                             (int)*(char*)(ctxLo + 0x12), texU, texV);
                            }
                        }
                    }
                    vtx = vtx + 8;
                }
            }
        }
    }
    FUN_80286878();
}

int hitanimator_getExtraSize(void) { return HITANIMATOR_EXTRA_STATE_BYTES; }

#pragma scheduling off
#pragma peephole off
void hitanimator_update(HitAnimatorObject* obj)
{
    HitAnimatorPlacement* setup = (HitAnimatorPlacement*)obj->objAnim.placementData;
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
    state->gameBitValue = (u8)GameBit_Get(setup->gameBit);
    if (state->previousGameBitValue != state->gameBitValue)
    {
        state->activeBit = state->activeBit ^ 1;
        if (setup->toggleMode == 1)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
        if ((setup->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((setup->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        }
    }
    state->previousGameBitValue = state->gameBitValue;
    if ((setup->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0)
    {
        if (fn_80065640() != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((state->flags & HITANIMATOR_STATE_FLAG_SOUND_PENDING) != 0)
        {
            if (fn_80065640() == 0)
            {
                fn_80065574(setup->soundId, (int)obj->objAnim.parent, state->activeBit);
                state->flags &= ~HITANIMATOR_STATE_FLAG_SOUND_PENDING;
            }
        }
    }
    if ((setup->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
    {
        if (setup->blockEffectId != 0)
        {
            if ((state->flags & HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING) != 0)
            {
                hitAnimatorFn_80193dbc(block, obj, state, setup);
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
    gameBitValue = (u8)GameBit_Get(desc->gameBit);
    state->gameBitValue = gameBitValue;
    state->previousGameBitValue = gameBitValue;
    obj->objectFlags |= HITANIMATOR_OBJECT_FLAGS_ENABLED;
}

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* state, HitAnimatorPlacement* desc)
{
    int i;
    char* poly;

    if ((desc->flags & 0x10) == 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->unk9A; i++)
        {
            poly = (char*)mapBlockFn_800606ec(block, i);
            if (desc->blockEffectId == mapBlockFn_80060678(poly))
            {
                if (state->activeBit != 0)
                {
                    *(u32*)(poly + 0x10) &= ~2LL;
                    if ((desc->flags & 0x2) != 0)
                    {
                        *(u32*)(poly + 0x10) &= ~1LL;
                    }
                }
                else
                {
                    *(int*)(poly + 0x10) |= 2;
                    if ((desc->flags & 0x2) != 0)
                    {
                        *(int*)(poly + 0x10) |= 1;
                    }
                }
            }
        }
    }
    if ((desc->flags & 0x2) != 0)
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
