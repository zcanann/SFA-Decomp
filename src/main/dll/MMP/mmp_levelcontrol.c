/* === moved from main/dll/MMP/mmp_barrel.c [80194408-8019443C) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"
#include "main/game_object.h"
#include "global.h"

typedef struct WaveanimatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 originX;
    s16 originY;
    s8 spanX;
    s8 spanY;
    s16 modelVariant;
    s8 unk20;
    s8 period;
    s8 gridN;
    u8 pad23[0x25 - 0x23];
    u8 unk25;
    u8 radius;
    u8 yOffset;
} WaveanimatorObjectDef;


typedef struct GroundanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x25 - 0x23];
    u8 unk25;
    u8 pad26[0x28 - 0x26];
} GroundanimatorPlacement;


typedef struct AlphaanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s8 unk1C;
    s8 unk1D;
    u8 active;
    u8 unk1F;
    u8 unk20;
    u8 pad21[0x22 - 0x21];
    u16 fadeMax;
    u16 sfxId;
    u8 pad26[0x28 - 0x26];
} AlphaanimatorPlacement;


/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */
typedef struct WaveAnimatorState
{
    int originX; /* 0x00 */
    int originY; /* 0x04 */
    int spanX; /* 0x08 */
    int spanY; /* 0x0c */
    f32 ampX; /* 0x10 */
    f32 ampY; /* 0x14 */
    int unk18; /* 0x18 */
    int period; /* 0x1c */
    int gridN; /* 0x20 */
    f32 minHeight; /* 0x24 */
    f32 maxHeight; /* 0x28 */
    f32 scaleA; /* 0x2c */
    f32 scaleB; /* 0x30 */
    u8 flags; /* 0x34: 1 = scale pending, 2 = func0B latch */
    u8 pad35[7];
} WaveAnimatorState;

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

/* alphaanimator_getExtraSize == 0x1c. */
typedef struct AlphaAnimatorState
{
    int vertCount; /* 0x00 */
    f32 fadeA; /* 0x04 */
    f32 fadeB; /* 0x08 */
    f32 fadeMax; /* 0x0c */
    void* buf; /* 0x10: mode-3 per-vertex alpha buffer */
    s16 alphaLevel; /* 0x14 */
    u8 active; /* 0x16 */
    u8 gateVal; /* 0x17 */
    u8 doneCount; /* 0x18 */
    u8 prevGate; /* 0x19 */
    u8 pad1A[2];
} AlphaAnimatorState;

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

/* groundanimator_getExtraSize == 0x30. */
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

/* visanimator_getExtraSize == 0x5. */
typedef struct VisAnimatorState
{
    u8 flags; /* 0x00: 1 = refresh pending */
    s8 visBit; /* 0x01 */
    u8 gateNow; /* 0x02 */
    u8 gatePrev; /* 0x03 */
    u8 gateMask; /* 0x04 */
} VisAnimatorState;

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern int FUN_80017a90();
extern undefined4 FUN_80017a98();
extern int FUN_80017af0();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_800480a0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern undefined4 FUN_8005ff38();
extern undefined4 FUN_8005ff90();
extern uint FUN_80060058();
extern int FUN_80060064();
extern undefined4 FUN_800600b4();
extern int FUN_800600e4();
extern undefined4 FUN_800631d4();
extern int FUN_80063298();
extern undefined4 FUN_801a8ae8();
extern undefined4 FUN_801a8b20();
extern undefined4 FUN_80242178();
extern uint FUN_80286810();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined8 FUN_8028682c();
extern uint FUN_80286840();
extern undefined4 TRKNubMainLoop();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de768;
extern undefined4 DAT_803de76c;
extern undefined4 DAT_803de770;
extern undefined4 DAT_803de774;
extern f64 DOUBLE_803e4c00;
extern f64 DOUBLE_803e4c20;
extern f64 DOUBLE_803e4c28;
extern f64 DOUBLE_803e4c38;
extern f64 DOUBLE_803e4c60;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E4BDC;
extern f32 lbl_803E4BE8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4BF0;
extern f32 lbl_803E4BF4;
extern f32 lbl_803E4BF8;
extern f32 lbl_803E4BFC;
extern f32 lbl_803E4C08;
extern f32 lbl_803E4C10;
extern f32 lbl_803E4C14;
extern f32 lbl_803E4C18;
extern f32 lbl_803E4C1C;
extern f32 lbl_803E4C30;
extern f32 lbl_803E4C40;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C48;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern f32 lbl_803E4C58;
extern f32 lbl_803E4C5C;

/*
 * --INFO--
 *
 * Function: waveanimator_func0B
 * EN v1.0 Address: 0x801923C4
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801923CC
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void waveanimator_func0B(int* obj);

u8 wallanimator_func0B(int* obj)
{
    int* p = ((int**)obj)[0xb8 / 4];
    return *p >= WALLANIMATOR_DONE_TIMER;
}
#pragma scheduling reset
#pragma peephole reset

extern void mm_free(void* p);

void alphaanimator_free(int* obj);

/*
 * --INFO--
 *
 * Function: FUN_80192488
 * EN v1.0 Address: 0x80192488
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801924D0
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192488(void);


/* Trivial 4b 0-arg blr leaves. */
void waveanimator_update(void);

void waveanimator_release(void);

void waveanimator_initialise(void);

void alphaanimator_hitDetect(void);

void alphaanimator_release(void);

void alphaanimator_initialise(void);

void visanimator_free(void);

void visanimator_render(void);

void visanimator_hitDetect(void);

void visanimator_release(void);

void visanimator_initialise(void);

/* 8b "li r3, N; blr" returners. */
int waveanimator_getExtraSize(void);
int waveanimator_getObjectTypeId(void);
int alphaanimator_getExtraSize(void);
int alphaanimator_getObjectTypeId(void);
int groundanimator_getExtraSize(void);
int hitanimator_getExtraSize(void);
int visanimator_getExtraSize(void);
int visanimator_getObjectTypeId(void);

/* Pattern wrappers. */
u8 groundanimator_modelMtxFn(int* obj);

/* 16b chained patterns. */
#pragma scheduling off
void alphaanimator_init(int* obj);
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3F70;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F78;
extern f32 lbl_803E3FC4;
#pragma peephole off
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset

/* wall variant: hashes lha to byte */
#pragma peephole off
u8 wallanimator_modelMtxFn(int* obj) { return (u8) * (s16*)((char*)((int**)obj)[0x4c / 4] + 0x1c); }

void waveanimator_setScale(int* obj, f32 fval);
#pragma peephole reset

extern f32 lbl_803E3F98;
#pragma scheduling off
u8 groundanimator_func0B(int* obj);
#pragma scheduling reset

extern int objPosToMapBlockIdx(double x, double y, double z);
extern void fn_801923F8(int* cfg);
extern void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate,
                                   HitAnimatorPlacement* desc);
extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern u8 lbl_803DDAE8;
#pragma peephole off
#pragma scheduling off
void waveanimator_init(int* obj, int* desc);
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void hitanimator_update(HitAnimatorObject* obj);
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E3FB8;
#pragma peephole off
#pragma scheduling off
void groundanimator_init(int* obj, int* desc);
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void hitanimator_init(HitAnimatorObject* obj, HitAnimatorPlacement* desc);
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void visanimator_init(int* obj, int* desc);

void visanimator_update(int* obj);
#pragma scheduling reset
#pragma peephole reset

extern void* lbl_803DDAEC;
extern void* lbl_803DDAF0;
extern void* lbl_803DDAF4;
#pragma peephole off
#pragma scheduling off
void waveanimator_free(int* obj);
#pragma scheduling reset
#pragma peephole reset
extern u8 lbl_803DDAF8;
extern u8 framesThisStep;
#pragma scheduling off
#pragma peephole off
void waveanimator_hitDetect(int* obj);

extern void fn_800605F0(void* cell, void* out);
extern void fn_8006058C(void* cell, void* in);
#pragma scheduling off
#pragma peephole off
void groundanimator_free(int* obj, int flag);

extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FAC;
extern f32 lbl_803E3FB0;
extern f32 lbl_803E3FB4;
extern f32 lbl_803E3FBC;
extern f32 timeDelta;
extern void fn_801A80F0(int* e, int arg);
#pragma scheduling off
#pragma peephole off
f32 groundanimator_setScale(int* obj, int* target);

extern float fastFloorf(float x);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3FC0;
#pragma scheduling off
#pragma peephole off
void fn_801932C8(int* obj, GroundAnimatorState* p2, int* p3);

extern int* Obj_GetPlayerObject(void);
extern int fn_80060688(void* block, int v);
extern void fn_801A80C4(void* o, f32 x, f32 y, f32 z);
extern void DCStoreRangeNoSync(void* addr, int len);
extern void* mmAlloc(int size, int align, int tag);
extern u16 lbl_803DBDF0[];
#pragma scheduling off
#pragma peephole off
void groundanimator_update(int* obj);

extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

void alphaanimator_update(int* obj);

extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 mathSinf(f32);

void fn_801923F8(int* cfgArg);


void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate, HitAnimatorPlacement* desc);
#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
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

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/MMP/mmp_levelcontrol.h"

typedef struct WallanimatorPlacement
{
    u8 pad0[0x1C - 0x0];
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} WallanimatorPlacement;


typedef struct WallanimatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} WallanimatorState;


typedef struct XyzanimatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} XyzanimatorState;


extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017748();
extern void vecRotateZXY(void* in, void* out);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern void* fn_800606FC(int* obj, int idx);
extern int objPosToMapBlockIdx(double x, double y, double z);
extern void mm_free(void* ptr);
extern void DCStoreRange(void* addr, u32 nBytes);
extern int return0_80060B90(void);
extern uint FUN_80060058();
extern undefined4 FUN_800600b4();
extern int FUN_800600d4();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286838();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();

extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e4c88;
extern f32 lbl_803E4C68;
extern f32 lbl_803E4C6C;
extern f32 lbl_803E4C70;
extern f32 lbl_803E4C74;
extern f32 lbl_803E4C78;
extern f32 lbl_803E4C7C;
extern f32 lbl_803E4C80;
extern f32 lbl_803E4C94;
extern f32 lbl_803E4C98;
extern f32 lbl_803E3FFC;
extern f32 lbl_803E4000;
extern f32 lbl_803E4008;
extern f64 lbl_803E4010;
extern f32 lbl_803E3FD0;
extern f32 lbl_803E3FD4;
extern f32 lbl_803E3FD8;
extern f32 lbl_803E3FDC;
extern f32 lbl_803E3FE0;
extern f32 lbl_803E3FE4;
extern f32 lbl_803E3FE8;
extern f32 lbl_803E3FEC;
extern f64 lbl_803E3FF0;

/*
 * --INFO--
 *
 * Function: wallanimator_setScale
 * EN v1.0 Address: 0x8019443C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80194688
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 wallanimator_setScale(int obj, int target)
{
    struct
    {
        s16 rot[3];
        char pad[6];
        f32 pos[3];
    } effect;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 out[3];
    int desc;
    int count;
    int* state;
    f32 scale;
    f32 kD0;
    f32 kD4;
    f32 kD8;
    f32 kDC;

    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    count = 6;
    kD0 = lbl_803E3FD0;
    kD4 = lbl_803E3FD4;
    kD8 = lbl_803E3FD8;
    kDC = lbl_803E3FDC;
    do
    {
        out[0] = kD0 * (f32)(int)
        randomGetRange(-0x64, 0x64);
        out[1] = kD4;
        out[2] = kD4;
        effect.rot[2] = (s16)randomGetRange(-0x7fff, 0x8000);
        effect.rot[1] = 0;
        effect.rot[0] = 0;
        vecRotateZXY(effect.rot, out);
        out[2] -= kD8;
        vecRotateZXY((void*)obj, out);
        effect.rot[2] = ((WallanimatorPlacement*)desc)->unk1C;
        effect.rot[0] = *(s16*)obj;
        effect.pos[0] = ((GameObject*)obj)->anim.worldPosX + out[0];
        effect.pos[1] = kDC + (((GameObject*)obj)->anim.worldPosY + out[1]);
        effect.pos[2] = ((GameObject*)obj)->anim.worldPosZ + out[2];
        (*gPartfxInterface)->spawnObject((void*)obj, 0xca, effect.rot, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0xcb, effect.rot, 0x200001, -1, NULL);
        count--;
    }
    while (count != 0);

    state = ((GameObject*)obj)->extra;
    deltaY = *(f32*)(target + 0x10) - ((GameObject*)obj)->anim.localPosY;
    if ((lbl_803E3FE0 > deltaY) || (lbl_803E3FE4 < deltaY))
    {
        scale = lbl_803E3FD4;
    }
    else
    {
        deltaX = *(f32*)(target + 0xc) - ((GameObject*)obj)->anim.localPosX;
        deltaZ = *(f32*)(target + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        if (deltaX * deltaX + deltaZ * deltaZ > lbl_803E3FE8)
        {
            scale = lbl_803E3FD4;
        }
        else
        {
            *state += 0x3c;
            scale = (f32) * state / lbl_803E3FEC;
        }
    }
    return scale;
}

/*
 * --INFO--
 *
 * Function: FUN_80194544
 * EN v1.0 Address: 0x80194544
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801947D4
 * EN v1.1 Size: 208b
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
 * Function: objFn_801948c0
 * EN v1.0 Address: 0x801948C0
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
f32 objFn_801948c0(u8* obj, u8 coord);

/*
 * --INFO--
 *
 * Function: FUN_80194a70
 * EN v1.0 Address: 0x80194A70
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80194E3C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80194a70(int param_1, byte param_2)
{
    int iVar1;

    if ((param_1 == 0) || (iVar1 = *(int*)&((GameObject*)param_1)->extra, iVar1 == 0))
    {
        return (double)lbl_803E4C98;
    }
    if (param_2 == 4)
    {
        return (double)*(float*)(iVar1 + 0x44);
    }
    if (param_2 < 4)
    {
        if (param_2 == 2)
        {
            return (double)*(float*)(iVar1 + 0x40);
        }
        if (1 < param_2)
        {
            return (double)(((GameObject*)param_1)->anim.localPosY + *(float*)(iVar1 + 0x44));
        }
        if (param_2 != 0)
        {
            return (double)(((GameObject*)param_1)->anim.localPosX + *(float*)(iVar1 + 0x40));
        }
    }
    else
    {
        if (param_2 == 6)
        {
            return (double)*(float*)(iVar1 + 0x48);
        }
        if (param_2 < 6)
        {
            return (double)(((GameObject*)param_1)->anim.localPosZ + *(float*)(iVar1 + 0x48));
        }
    }
    return (double)lbl_803E4C98;
}

/*
 * --INFO--
 *
 * Function: FUN_80194b10
 * EN v1.0 Address: 0x80194B10
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80194EE0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


typedef struct MapBlockHdr
{
    u16 start;
    u16 pad1[2];
    s16 posA;
    s16 posB;
} MapBlockHdr;

typedef struct VertexS16
{
    s16 x;
    s16 y;
    s16 z;
} VertexS16;

typedef struct EdgeVerts
{
    u8 pad[6];
    s16 a;
    s16 b;
    s16 c;
    s16 d;
    s16 e;
    s16 f;
} EdgeVerts;

#pragma scheduling off
#pragma peephole off
void fn_80194964(int obj, int state, int block);

void fn_80194C40(undefined4 def, int state, int block);

/*
 * --INFO--
 *
 * Function: wallanimator_getExtraSize
 * EN v1.0 Address: 0x8019469C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wallanimator_getExtraSize(void)
{
    return 8;
}

/*
 * --INFO--
 *
 * Function: xyzanimator_getExtraSize
 * EN v1.0 Address: 0x80194B5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int xyzanimator_getExtraSize(void);

void xyzanimator_free(int obj, int param_2);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3FF8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4004;

void wallanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3FF8);
}

void xyzanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void wallanimator_free(int obj)
{
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_SECONDARY);
}

void wallanimator_update(int obj)
{
    extern void objRenderFn_80041018(int obj); /* #57 */
    extern int getTrickyObject(void); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    int nearby;
    int* state;
    int desc;
    int tricky;
    float nearestDistance[4];

    state = ((GameObject*)obj)->extra;
    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode | 8;

    if (((u32) * (u8*)(state + 1) >> 7) != 0)
    {
        return;
    }

    if (*state >= WALLANIMATOR_DONE_TIMER)
    {
        u8 activeBit = 1;
        *(u8*)(state + 1) =
            (*(u8*)(state + 1) & ~WALLANIMATOR_RUNTIME_ACTIVE_FLAG) | (activeBit << 7);
        GameBit_Set((int)*(short*)(desc + 0x18), 1);
        Sfx_PlayFromObject(obj, WALLANIMATOR_COMPLETE_SFX);
        return;
    }

    tricky = getTrickyObject();
    if ((void*)tricky != NULL)
    {
        nearestDistance[0] = lbl_803E3FFC;
        nearby = ObjGroup_FindNearestObject(WALLANIMATOR_NEARBY_GROUP, obj, nearestDistance);
        if ((void*)nearby == NULL)
        {
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode & ~
                0x10;
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode & ~8;
            if ((*(byte*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                (*(code*)(**(int**)(tricky + 0x68) + 0x28))(tricky, obj, 1, 1);
            }
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10;
    }
}

void wallanimator_init(s16* obj, s16* p2)
{
    register int* state = ((GameObject*)obj)->extra;

    *obj = (s16)p2[0x24 / 2];
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_SECONDARY);
    if (GameBit_Get((int)p2[0x18 / 2]) != 0)
    {
        ((WallanimatorState*)state)->unk4 |= WALLANIMATOR_RUNTIME_ACTIVE_FLAG;
        *state = WALLANIMATOR_DONE_TIMER;
    }
}
