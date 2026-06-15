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

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern u8 framesThisStep;

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

volatile FbWGPipe GXWGFifo : (0xCC008000);

/* segment pragma-stack balance (re-split): */

#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"

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

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern undefined4 FUN_800067c0();
extern undefined8 ObjGroup_RemoveObject();
extern int** ObjGroup_GetObjects(int group, int* countOut);

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

#pragma scheduling off
#pragma peephole off
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

int dll_1CF_getExtraSize(void);
int dim2pathgenerator_getExtraSize(void) { return 0x9a8; }
int dim2pathgenerator_getObjectTypeId(void) { return 0x0; }

void dim_tricky_init(int* obj);

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
    int n;
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
            int found;
            n = 21;
            found = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &n, 1, 10);
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
    if ((((Dim2PathGeneratorState*)extra)->spawnTimer -= framesThisStep) > 0)
    {
        return;
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
            int j;
            int** o2;
            *(f32*)((char*)p + 8) = ((Dim2PathGeneratorState*)extra)->originX;
            *(f32*)((char*)p + 0xc) = ((Dim2PathGeneratorState*)extra)->originY;
            *(f32*)((char*)p + 0x10) = ((Dim2PathGeneratorState*)extra)->originZ;
            *(int*)((char*)p + 0x14) = ((Dim2pathgeneratorPlacement*)def)->unk14;
            (*(void (**)(int*, int*, int))(**(int**)((char*)objs[i] + 0x68) + 4))(objs[i], p, 1);
            ObjGroup_RemoveObject(objs[i], 47);
            o2 = ObjGroup_GetObjects(47, &count);
            for (j = 0; j < count; j++)
            {
            }
            ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
            return;
        }
    }
    if (Obj_IsLoadingLocked())
    {
        int* np = (int*)Obj_AllocObjectSetup(36, ((volatile s16*)((Dim2PathGeneratorState*)extra)->spawnTypes)[toggle]);
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
