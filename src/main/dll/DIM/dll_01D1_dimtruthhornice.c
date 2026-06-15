/* DLL 0x1D1 - DIMTruthHornIce [801B63F4-801B6464) */
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/explosion_state.h"
#include "main/objseq.h"

/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped. REFERENCE-ONLY for now:
 * every consumer keeps raw derefs - retyping the state local (or adding
 * (int) casts) flips saved-reg coloring in init/update/render/fn_801B3DE4
 * (recipe #36/#77); the layout is documented here for a future pass.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

extern f32 timeDelta;

volatile FbWGPipe GXWGFifo : (0xCC008000);

/* segment pragma-stack balance (re-split): */

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

typedef struct DimtruthhorniceObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 hitsLeft;
    s16 unk1C;
    s16 gameBit;
} DimtruthhorniceObjectDef;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern undefined4 FUN_800067c0();
extern undefined4 ObjHits_DisableObject();
extern int* getTrickyObject(void);
extern f32 lbl_803E4A40;
extern f32 lbl_803E4A44;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling on
#pragma peephole on
void FUN_801b7314(int param_1, undefined4 param_2, float* param_3, float* param_4)
{
    uint uVar1;
    int iVar2;
    float* pfVar3;

    pfVar3 = ((GameObject*)param_1)->extra;
    if (pfVar3[4] == 0.0)
    {
        FUN_800067c0((int*)0xdf, 1);
    }
    pfVar3[4] = 2.8026e-44;
    iVar2 = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    if (iVar2 == 0x49b23)
    {
        uVar1 = GameBit_Get(0xc5c);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5b), uVar1 == 0))
        {
            *param_3 = *pfVar3;
            *param_4 = pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5c), uVar1 == 0))
        {
            *param_3 = -*pfVar3;
            *param_4 = -pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 != 0)
        {
            GameBit_Set(0xc5c, 0);
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 == 0)
        {
            GameBit_Set(0xc5c, 1);
        }
    }
    else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9))
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    else
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    return;
}

void dll_1CF_free(void);

int dimtruthhornice_getExtraSize(void) { return 0x8; }
int dim2conveyor_getExtraSize(void);

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */
#pragma scheduling off
#pragma peephole off
int fn_801B6D40(int* obj, int v)
{
    u8* state = ((GameObject*)obj)->extra;
    *(s8*)(state + 2) = (s8)(state[2] - v);
    return *(s8*)(state + 2) <= 0;
}

u8 dim2pathgenerator_getCurveVals(int* obj, int** p1, int** p2, int** p3, int** p4);

void dimtruthhornice_init(int* obj, int* def)
{
    TruthHornIceState* state = ((GameObject*)obj)->extra;
    state->hitsLeft = (s8)((DimtruthhorniceObjectDef*)def)->hitsLeft;
    state->gameBit = ((DimtruthhorniceObjectDef*)def)->gameBit;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
    {
        s16 slot = state->gameBit;
        if (slot != -1 && (u32)GameBit_Get(slot) != 0u)
        {
            ObjHits_DisableObject(obj);
            state->phase = 2;
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

void dim2snowball_init(int* obj, int* def);

void dimtruthhornice_update(int* obj)
{
    extern int Sfx_PlayFromObject(int obj, int sfxId);
    TruthHornIceState* extra = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    switch (extra->phase)
    {
    case 0:
        if (extra->hitsLeft <= 0)
        {
            if (extra->gameBit != -1)
            {
                GameBit_Set(extra->gameBit, 1);
                ObjHits_DisableObject(obj);
                extra->phase = 1;
                extra->timer = lbl_803E4A40;
            }
        }
        else
        {
            int* tricky = (int*)getTrickyObject();
            if (tricky != NULL)
            {
                if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                {
                    (*(void (**)(int*, int*, int, int))(**(int**)((char*)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            }
        }
        break;
    case 1:
        {
            f32 desc[6];
            extra->timer = extra->timer + timeDelta;
            if (extra->timer > lbl_803E4A44)
            {
                int i;
                extra->phase = 2;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                Sfx_PlayFromObject((int)obj, 1147);
                for (i = 30; i != 0; i--)
                {
                    desc[3] = 0.1f * (f32)(int)
                    randomGetRange(-100, 100);
                    desc[4] = 0.1f * (f32)(int)
                    randomGetRange(0, 350);
                    desc[5] = 0.1f * (f32)(int)
                    randomGetRange(-100, 100);
                    desc[2] = 1.0f;
                    (*gPartfxInterface)->spawnObject(obj, 2043, desc, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject(obj, 2044, desc, 2, -1, NULL);
                }
            }
            desc[3] = 0.1f * (f32)(int)
            randomGetRange(-100, 100);
            desc[4] = 0.1f * (f32)(int)
            randomGetRange(0, 350);
            desc[5] = 0.1f * (f32)(int)
            randomGetRange(-100, 100);
            desc[2] = 1.0f;
            (*gPartfxInterface)->spawnObject(obj, 2044, desc, 2, -1, NULL);
            break;
        }
    case 2:
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    }
}
