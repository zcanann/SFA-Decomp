#include "main/objanim_internal.h"
#include "main/game_object.h"
#include "main/dll/DR/DRsimplehuman.h"

typedef struct SpitembeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} SpitembeamPlacement;


typedef struct SpdrapeObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} SpdrapeObjectDef;


typedef struct SpdrapeState
{
    u8 pad0[0x10 - 0x0];
    s32 unk10;
    s16 unk14;
    u8 unk16;
    u8 pad17[0x18 - 0x17];
} SpdrapeState;


extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_800069a8();
extern double FUN_80017708();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_8001777c();
extern undefined4 FUN_80017958();
extern int FUN_80017a54();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern undefined FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjGroup_AddObject();
extern int FUN_800620e8();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801e8278();
extern undefined4 FUN_801e85b0();
extern undefined4 FUN_801f4f98();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd18;
extern undefined4 DAT_803dcd1c;
extern undefined4 DAT_803e6708;
extern undefined4 DAT_803e670a;
extern f64 DOUBLE_803e6730;
extern f32 lbl_803DC074;
extern f32 lbl_803E670C;
extern f32 lbl_803E6710;
extern f32 lbl_803E6718;
extern f32 lbl_803E671C;
extern f32 lbl_803E6720;
extern f32 lbl_803E672C;
extern f32 lbl_803E6738;
extern f32 lbl_803E673C;
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;
extern f32 lbl_803E6748;
extern f32 lbl_803E674C;
extern f32 lbl_803E6750;
extern f32 lbl_803E6754;

/*
 * --INFO--
 *
 * Function: spdrape_update
 * EN v1.0 Address: 0x801E9344
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E93B4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void* Obj_GetPlayerObject(void);
extern f32 getXZDistance(f32 * a, f32 * b);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Camera_GetCurrentViewSlot(void);
extern f32 lbl_803DC0B0;
extern f32 lbl_803DC0B4;
extern byte framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5AA0;
extern f32 lbl_803E5AA4;
extern f32 lbl_803E5AA8;
extern f32 lbl_803E5AAC;
extern f32 lbl_803E5AB0;
extern f32 lbl_803E5AB4;
extern f32 lbl_803E5AB8;
extern f32 lbl_803E5ABC;

void spdrape_update(int obj)
{
    f32* state;
    char* player;

    state = ((GameObject*)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0:
        if ((s16)(((SpdrapeState*)state)->unk14 -= framesThisStep) <= 0)
        {
            Sfx_PlayFromObject(obj, 0x13f);
            ((SpdrapeState*)state)->unk14 = randomGetRange(0xb4, 300);
        }
        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E5AA4)
        {
            if (player != 0)
            {
                if (state[3] + (state[1] * *(f32*)(player + 0xc) + state[2] * *(f32*)(player + 0x14)) < lbl_803E5AA0)
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B0;
                }
                else
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B4;
                }
            }
            ObjAnim_SetCurrentMove(obj, **(u8**)&((SpdrapeState*)state)->unk10, lbl_803E5AA0, 0);
            *state = lbl_803E5AA8;
            Sfx_PlayFromObject(obj, 0x140);
            Camera_GetCurrentViewSlot();
        }
        break;
    case 1:
    case 4:
        if (((SpdrapeState*)state)->unk16 != 0)
        {
            if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) > lbl_803E5AAC)
            {
                ObjAnim_SetCurrentMove(obj, (*(u8**)&((SpdrapeState*)state)->unk10)[2], lbl_803E5AA0, 0);
                Sfx_PlayFromObject(obj, 0x140);
                *state = lbl_803E5AB0;
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, (*(u8**)&((SpdrapeState*)state)->unk10)[1], lbl_803E5AA0, 0);
                *state = lbl_803E5AB4;
            }
        }
        break;
    case 2:
    case 5:
        Sfx_PlayFromObject(obj, 0x141);
        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) > lbl_803E5AAC)
        {
            ObjAnim_SetCurrentMove(obj, (*(u8**)&((SpdrapeState*)state)->unk10)[2], lbl_803E5AA0, 0);
            Sfx_StopObjectChannel(obj, 0x40);
            Sfx_PlayFromObject(obj, 0x140);
            *state = lbl_803E5AB0;
        }
        break;
    case 3:
    case 6:
        if ((((GameObject*)obj)->anim.currentMoveProgress > lbl_803E5AB8) && (getXZDistance(
            &((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E5AA4))
        {
            if (player != 0)
            {
                if (state[3] + (state[1] * *(f32*)(player + 0xc) + state[2] * *(f32*)(player + 0x14)) < lbl_803E5AA0)
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B0;
                }
                else
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B4;
                }
            }
            ObjAnim_SetCurrentMove(obj, **(u8**)&((SpdrapeState*)state)->unk10, lbl_803E5AA0, 0);
            Sfx_PlayFromObject(obj, 0x140);
            *state = lbl_803E5AA8;
        }
        else if (((SpdrapeState*)state)->unk16 != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5AA0, 0);
            *state = lbl_803E5ABC;
            Camera_GetCurrentViewSlot();
        }
        break;
    }
    ((SpdrapeState*)state)->unk16 = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
        obj, *state, timeDelta, NULL);
}


/*
 * --INFO--
 *
 * Function: FUN_801e9368
 * EN v1.0 Address: 0x801E9368
 * EN v1.0 Size: 808b
 * EN v1.1 Address: 0x801E9518
 * EN v1.1 Size: 588b
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
 * Function: FUN_801e983c
 * EN v1.0 Address: 0x801E983C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E997C
 * EN v1.1 Size: 760b
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
 * Function: spitembeam_init
 * EN v1.0 Address: 0x801E9900
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void spitembeam_init(int obj)
{
    ((GameObject*)obj)->objectFlags = (ushort)(((GameObject*)obj)->objectFlags | 0x6000);
}


/* Trivial 4b 0-arg blr leaves. */
void spdrape_release(void)
{
}

void spdrape_initialise(void)
{
}

void spitembeam_free(void)
{
}

void spitembeam_render(void)
{
}

void spitembeam_hitDetect(void)
{
}

void spitembeam_release(void)
{
}

void spitembeam_initialise(void)
{
}

extern int* ObjGroup_FindNearestObject(int group, int* obj, f32* dist);
extern int* objFindTexture(int* obj, int a, int b);
extern f32 lbl_803E5AD8;

void spitembeam_update(int* obj)
{
    int* target;
    u8* def;
    int* tex;
    f32 d;

    target = *(int**)&((GameObject*)obj)->unkF4;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    d = lbl_803E5AD8;
    if (target == NULL)
    {
        *(int**)&((GameObject*)obj)->unkF4 = ObjGroup_FindNearestObject(9, obj, &d);
    }
    else
    {
        if (((int(*)(int*, s16))(**(int***)((char*)target + 0x68))[10])(target, ((SpitembeamPlacement*)def)->unk1A) == 0
            || ((int(*)(int*, s16))(**(int***)((char*)target + 0x68))[11])(target, ((SpitembeamPlacement*)def)->unk1A)
            != 0)
        {
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            *(s16*)((char*)tex + 8) += 8;
            if (*(s16*)((char*)tex + 8) > 0x400)
            {
                *(s16*)((char*)tex + 8) -= 0x400;
            }
        }
    }
}

/* 8b "li r3, N; blr" returners. */
int spitembeam_getExtraSize(void) { return 0x0; }
int spitembeam_getObjectTypeId(void) { return 0x0; }

extern f32 lbl_803E5AC0;
extern f32 lbl_803E5AC4;
extern f32 lbl_803E5AC8;
extern f32 lbl_803E5ACC;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern unsigned long randomGetRange(int a, int b);

void spdrape_init(int* obj, u8* def)
{
    f32* state;
    int* player;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((GameObject*)obj)->objectFlags |= 0x4000;
    *(s16*)obj = (s16)((s32)((SpdrapeObjectDef*)def)->unk18 << 8);
    if (((SpdrapeObjectDef*)def)->unk1A != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(s32)((SpdrapeObjectDef*)def)->unk1A / lbl_803E5AC4 *
            lbl_803E5AC0;
    }
    state[0] = lbl_803E5ABC;
    state[1] = mathSinf(lbl_803E5AC8 * (f32)(s32) * (s16*)obj / lbl_803E5ACC);
    state[2] = mathCosf(lbl_803E5AC8 * (f32)(s32) * (s16*)obj / lbl_803E5ACC);
    state[3] = -(state[1] * ((GameObject*)obj)->anim.localPosX + state[2] * ((GameObject*)obj)->anim.localPosZ);
    ((SpdrapeState*)state)->unk14 = (s16)randomGetRange(0xb4, 0x12c);
    player = (int*)Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (state[1] * ((GameObject*)player)->anim.localPosX + state[2] * ((GameObject*)player)->anim.localPosZ + state[
            3] < lbl_803E5AA0)
        {
            ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B0;
        }
        else
        {
            ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B4;
        }
    }
}

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} ShWGPipe;

volatile ShWGPipe GXWGFifo : (0xCC008000);

static inline void shPos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void shColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void shTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

typedef struct
{
    u8 r, g, b, a;
} ShColor;

extern void selectTexture(int tex, int p);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void textRenderSetupFn_80079804(void);
extern void GXSetTevColor(int reg, ShColor color);
extern void gxSetZMode_(int a, int b, int c);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void gxSetPeControl_ZCompLoc_(int a);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXSetCullMode(int mode);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern f32* Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXSetCurrentMtx(int id);
extern void getAmbientColor(int mode, u8* r, u8* g, u8* b);
extern void GXBegin(int prim, int fmt, int n);
extern int lbl_803DDC60;
extern ShColor lbl_803E5AE4;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

/*
 * --INFO--
 *
 * Function: fn_801E991C
 * EN v1.0 Address: 0x801E991C
 * EN v1.0 Size: 740b
 */
#pragma opt_common_subs off
void fn_801E991C(int p1, char* table)
{
    u8 r;
    u8 g;
    u8 b;
    ShColor color;
    char* p;
    int i;

    color = lbl_803E5AE4;
    selectTexture(lbl_803DDC60, 0);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    textRenderSetupFn_80079804();
    GXSetTevColor(2, color);
    gxSetZMode_(1, 3, 0);
    GXSetBlendMode(1, 4, 5, 5);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    getAmbientColor(0, &r, &g, &b);
    p = table;
    for (i = 0; i < 9; i++)
    {
        if (((*(u8*)(p + 0x4ce) & 1) != 0) && (*(s16*)(p + 0x4cc) >= 4))
        {
            int j = 0;
            f32* verts;
            f32 u1, u0;
            verts = *(f32**)(p + 0x4c8);
            u0 = lbl_803E5AE8;
            u1 = lbl_803E5AEC;
            for (; j < *(s16*)(p + 0x4cc) - 2; j += 2)
            {
                GXBegin(0x80, 2, 4);
                shPos3f32(verts[0] - playerMapOffsetX, verts[0 + 1], verts[0 + 2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8) * (s16*)((char*)verts + 0xc));
                shTexCoord2f32(u0, u0);
                GXWGFifo.f32 = u0;
                shPos3f32(verts[4] - playerMapOffsetX, verts[4 + 1], verts[4 + 2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8) * (s16*)((char*)verts + 0x1c));
                shTexCoord2f32(u1, u0);
                shPos3f32(verts[0xc] - playerMapOffsetX, verts[0xc + 1], verts[0xc + 2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8) * (s16*)((char*)verts + 0x3c));
                shTexCoord2f32(u1, u0);
                shPos3f32(verts[8] - playerMapOffsetX, verts[8 + 1], verts[8 + 2] - playerMapOffsetZ);
                shColor4u8(r, g, b, (u8) * (s16*)((char*)verts + 0x2c));
                shTexCoord2f32(u0, u0);
                GXWGFifo.f32 = u0;
                verts += 8;
            }
        }
        p += 8;
    }
}
#pragma opt_common_subs reset
