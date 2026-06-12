/* === moved from main/dll/DIM/DIM2flameburst.c [801B63F4-801B6464) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
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
#include "main/effect_interfaces.h"
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


/*
 * --INFO--
 *
 * Function: FUN_801b3de4
 * EN v1.0 Address: 0x801B3DE4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801B401C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801b40f0
 * EN v1.0 Address: 0x801B40F0
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x801B4398
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: explosion_release
 * EN v1.0 Address: 0x801B5650
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B5DB8
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma scheduling off
#pragma peephole off

#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b5b8c
 * EN v1.0 Address: 0x801B5B8C
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801B62FC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801b5d00
 * EN v1.0 Address: 0x801B5D00
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801B64D0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */













#pragma scheduling off
#pragma peephole off

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */





/* conditional init/free pair. */
#pragma scheduling on
#pragma peephole on

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */
#pragma scheduling off

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */
#pragma peephole off


/* explosion_free: model-light release if present. */
#pragma scheduling on
#pragma peephole on

/* explosion_getObjectTypeId: tile/index lookup capped by table count. */
#pragma scheduling off

/* dim_levelcontrol_free: gameplay music + time-of-day reset. */


/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern u8 framesThisStep;
#pragma dont_inline on
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */
#pragma peephole off


/* EN v1.0 0x801B5804  size: 380b  dimwooddoor2_update: advance the door's
 * shake anim and decay its wobble; while idle near map-cue 0x338 bleed off
 * alpha, otherwise scan the nearby objects and, if a key object is present,
 * snap the door open (reset wobble, ring the gamebit, play the open sfx). */


/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */



volatile FbWGPipe GXWGFifo : (0xCC008000);











#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/asset_load.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIM2snowball.h"
#include "main/objanim_internal.h"









typedef struct Dim2pathgeneratorObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 spawnPeriod;
    s16 unk1A;
    s16 unk1C;
    u16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} Dim2pathgeneratorObjectDef;


typedef struct Dim2pathgeneratorPlacement
{
    u8 pad0[0x3 - 0x0];
    u8 unk3;
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x14 - 0x8];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u16 unk1E;
    s16 unk20;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} Dim2pathgeneratorPlacement;


/* dim2conveyor_getExtraSize == 0x14. */


STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

/* dll_1D6_getExtraSize == 0x20 (crusher platform). */


STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

/* dimtruthhornice_getExtraSize == 0x8. */


STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

/* dim2snowball_getExtraSize == 0xb0 (curve walker head + roll state). */


STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */


STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_800067c0();
extern undefined8 ObjGroup_RemoveObject();


/*
 * --INFO--
 *
 * Function: dim_levelcontrol_update
 * EN v1.0 Address: 0x801B6464
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x801B6A18
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/*
 * --INFO--
 *
 * Function: FUN_801b6d24
 * EN v1.0 Address: 0x801B6D24
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801B6F60
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b6f88
 * EN v1.0 Address: 0x801B6F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801B71F4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b6fa8
 * EN v1.0 Address: 0x801B6FA8
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801B721C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b7314
 * EN v1.0 Address: 0x801B7314
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B7708
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_801b7fcc
 * EN v1.0 Address: 0x801B7FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B8344
 * EN v1.1 Size: 1344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b7fd0
 * EN v1.0 Address: 0x801B7FD0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B8884
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_1CF_free(void);

















void dim2pathgenerator_free(void)
{
}

void dim2pathgenerator_render(void)
{
}

void dim2pathgenerator_hitDetect(void)
{
}

void dim2pathgenerator_release(void)
{
}

void dim2pathgenerator_initialise(void)
{
}


/* 8b "li r3, N; blr" returners. */
int dll_1CF_getExtraSize(void);
int dim2pathgenerator_getExtraSize(void) { return 0x9a8; }
int dim2pathgenerator_getObjectTypeId(void) { return 0x0; }

/* 16b chained patterns. */
void dim_tricky_init(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */






/* render-with-fn(lbl) (no visibility check). */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */



/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */

extern u8 lbl_803DBF20;

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */

u8 dim2pathgenerator_getCurveVals(int* obj, int** p1, int** p2, int** p3, int** p4)
{
    int* state = ((GameObject*)obj)->extra;
    *p1 = (int*)((char*)state + 12);
    *p2 = (int*)((char*)state + 812);
    *p3 = (int*)((char*)state + 1612);
    if (p4 != NULL)
    {
        *p4 = (int*)((char*)state + 2412);
    }
    return ((Dim2PathGeneratorState*)state)->curveValid;
}

void dll_1D6_free(int* obj);

void dim2pathgenerator_init(int* obj, int* def)
{
    Dim2PathGeneratorState* state;
    *(s16*)obj = (s16)((u32) * (u8*)((char*)def + 28) << 8);
    state = ((GameObject*)obj)->extra;
    state->spawnPeriod = ((Dim2pathgeneratorObjectDef*)def)->spawnPeriod;
    state->spawnTimer = (s16) * (u8*)((char*)def + 29);
    state->spawnTypes[0] = (s16)((Dim2pathgeneratorObjectDef*)def)->unk1E;
    {
        s16 v = ((Dim2pathgeneratorObjectDef*)def)->unk20;
        if (v == -1)
        {
            state->spawnTypes[1] = (s16)((Dim2pathgeneratorObjectDef*)def)->unk1E;
        }
        else
        {
            state->spawnTypes[1] = v;
        }
    }
    state->flags = (u8)(state->flags | 4);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

void dimtruthhornice_init(int* obj, int* def);









extern void* mmAlloc(int size, int a, int b);




extern int** ObjGroup_GetObjects(int group, int* countOut);

void dim2pathgenerator_update(int* obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
    extern int Obj_AllocObjectSetup(int kind, int id);
    int* def;
    int* extra = ((GameObject*)obj)->extra;
    int toggle;
    int** objs;
    int i;
    int count;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((Dim2pathgeneratorPlacement*)def)->unk22) == 0)
    {
        return;
    }
    if ((((Dim2PathGeneratorState*)extra)->flags & 4) != 0)
    {
        if ((((Dim2PathGeneratorState*)extra)->flags & 2) == 0)
        {
            int n = 21;
            int found = (*gRomCurveInterface)->find(&n, 1, 10, ((GameObject*)obj)->anim.localPosX,
                                                    ((GameObject*)obj)->anim.localPosY,
                                                    ((GameObject*)obj)->anim.localPosZ);
            if (found != -1)
            {
                int* cv = (int*)(*gRomCurveInterface)->getById(found);
                ((void (*)(int))(*gRomCurveInterface)->slot74)((int)cv);
                ((Dim2PathGeneratorState*)extra)->curveValid =
                    ((int (*)(int*, void*, void*, void*, void*))(*gRomCurveInterface)->slot78)(
                        cv, (char*)extra + 0xc, (char*)extra + 0x32c, (char*)extra + 0x64c,
                        (char*)extra + 0x96c);
                ((Dim2PathGeneratorState*)extra)->flags |= 2;
                ((Dim2PathGeneratorState*)extra)->originX = *(f32*)((char*)cv + 8);
                ((Dim2PathGeneratorState*)extra)->originY = *(f32*)((char*)cv + 0xc);
                ((Dim2PathGeneratorState*)extra)->originZ = *(f32*)((char*)cv + 0x10);
            }
        }
    }
    else
    {
        ((Dim2PathGeneratorState*)extra)->originX = ((GameObject*)obj)->anim.localPosX;
        ((Dim2PathGeneratorState*)extra)->originY = ((GameObject*)obj)->anim.localPosY;
        ((Dim2PathGeneratorState*)extra)->originZ = ((GameObject*)obj)->anim.localPosZ;
    }
    {
        s16 t = ((Dim2PathGeneratorState*)extra)->spawnTimer - framesThisStep;
        ((Dim2PathGeneratorState*)extra)->spawnTimer = t;
        if (t > 0)
        {
            return;
        }
    }
    toggle = ((Dim2PathGeneratorState*)extra)->flags & 1;
    ((Dim2PathGeneratorState*)extra)->spawnTimer = ((Dim2PathGeneratorState*)extra)->spawnPeriod;
    ((Dim2PathGeneratorState*)extra)->flags &= ~1;
    objs = ObjGroup_GetObjects(47, &count);
    for (i = 0; i < count; i++)
    {
        if (((Dim2PathGeneratorState*)extra)->spawnTypes[toggle] == *(s16*)((char*)objs[i] + 0x46))
        {
            int* p = *(int**)((char*)objs[i] + 0x4c);
            int c2;
            int j;
            int** o2;
            *(f32*)((char*)p + 8) = ((Dim2PathGeneratorState*)extra)->originX;
            *(f32*)((char*)p + 0xc) = ((Dim2PathGeneratorState*)extra)->originY;
            *(f32*)((char*)p + 0x10) = ((Dim2PathGeneratorState*)extra)->originZ;
            *(int*)((char*)p + 0x14) = ((Dim2pathgeneratorPlacement*)def)->unk14;
            (*(void (**)(int*, int))(**(int**)((char*)objs[i] + 0x68) + 4))(objs[i], 1);
            ObjGroup_RemoveObject(objs[i], 47);
            o2 = ObjGroup_GetObjects(47, &c2);
            for (j = 0; j < c2; j++)
            {
            }
            ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
            return;
        }
    }
    if (Obj_IsLoadingLocked())
    {
        int* np = (int*)Obj_AllocObjectSetup(36, ((Dim2PathGeneratorState*)extra)->spawnTypes[toggle]);
        *(f32*)((char*)np + 8) = ((Dim2PathGeneratorState*)extra)->originX;
        *(f32*)((char*)np + 0xc) = ((Dim2PathGeneratorState*)extra)->originY;
        *(f32*)&((ObjDef*)np)->jointData = ((Dim2PathGeneratorState*)extra)->originZ;
        *(u8*)((char*)np + 4) = ((Dim2pathgeneratorPlacement*)def)->unk4;
        *(u8*)((char*)np + 6) = ((Dim2pathgeneratorPlacement*)def)->unk6;
        *(u8*)((char*)np + 5) = ((Dim2pathgeneratorPlacement*)def)->unk5;
        *(u8*)((char*)np + 7) = ((Dim2pathgeneratorPlacement*)def)->unk7;
        *(u8*)((char*)np + 7) = 255;
        *(u8*)((char*)np + 3) = ((Dim2pathgeneratorPlacement*)def)->unk3;
        *(s8*)((char*)np + 0x18) = (s8) * (u8*)((char*)def + 0x1c);
        *(s16*)((char*)np + 0x1a) = *(u8*)((char*)def + 0x1a);
        *(s16*)((char*)np + 0x1c) = *(u8*)((char*)def + 0x1b);
        *(int*)((char*)np + 0x14) = ((Dim2pathgeneratorPlacement*)def)->unk14;
        Obj_SetupObject((int)np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
        ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
    }
}

extern void mtxRotateByVec3s(f32 * mtx, s16 * ang);



