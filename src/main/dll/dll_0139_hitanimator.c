/* DLL 0x0139 — hitanimator (hit-reaction animation driver). TU: 0x80193DBC–0x8019423C. */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"

extern uint GameBit_Get(int eventId);

extern void* mapGetBlock(int idx);

#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern int FUN_80017af0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();

#pragma scheduling on
#pragma peephole on
extern void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate,
                                   HitAnimatorPlacement* desc);
extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern void* mapBlockFn_800606ec(void* block, int idx);
extern int mapBlockFn_80060678(void* entry);
extern u8* Shader_getLayer(char* s, int layer);

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
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx = polyIdx + 1)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx = vtxIdx + 1)
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
                            if ((mapId == 0x49b2f) || (mapId == 0x49b67))
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
    return;
}


int hitanimator_getExtraSize(void) { return 0x4; }
int visanimator_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void hitanimator_update(HitAnimatorObject* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
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
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    HitAnimatorState* state = obj->state;
    void* block;
    u8 g;
    s8 init_bit;
    init_bit = (s8)(desc->flags & HITANIMATOR_SETUP_FLAG_INITIAL_INVERT);
    state->activeBit = init_bit;
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
    g = (u8)GameBit_Get(desc->gameBit);
    state->gameBitValue = g;
    state->previousGameBitValue = g;
    obj->objectFlags |= HITANIMATOR_OBJECT_FLAGS_ENABLED;
}

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate, HitAnimatorPlacement* desc)
{
    extern char* fn_8006070C(void* block, int idx); /* #57 */
    int i;
    char* m;

    if ((desc->flags & 0x10) == 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->unk9A; i++)
        {
            m = (char*)mapBlockFn_800606ec(block, i);
            if (desc->blockEffectId == mapBlockFn_80060678(m))
            {
                if (vstate->activeBit != 0)
                {
                    *(u32*)(m + 0x10) &= ~2LL;
                    if ((desc->flags & 0x2) != 0)
                    {
                        *(u32*)(m + 0x10) &= ~1LL;
                    }
                }
                else
                {
                    *(int*)(m + 0x10) |= 2;
                    if ((desc->flags & 0x2) != 0)
                    {
                        *(int*)(m + 0x10) |= 1;
                    }
                }
            }
        }
    }
    if ((desc->flags & 0x2) != 0)
    {
        for (i = 0; i < *((u8*)block + 0xa2); i++)
        {
            char* s = fn_8006070C(block, i);
            u8* layer = Shader_getLayer(s, 0);
            if (desc->blockEffectId == layer[5])
            {
                if (vstate->activeBit != 0)
                {
                    *(u32*)(s + 0x3c) &= ~2LL;
                }
                else
                {
                    *(int*)(s + 0x3c) |= 2;
                }
            }
        }
    }
}
