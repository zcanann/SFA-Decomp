/* === moved from main/dll/DR/DRCloudball.c [801E9328-801E9344) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/DR/dll_0287_spscarab.h"





extern void Sfx_PlayFromObject(int obj, int sfxId);

extern f32 timeDelta;

extern void spscarab_hitDetect(void);
extern void spscarab_render(void);
extern void spscarab_free(int x);
extern int spscarab_getObjectTypeId(void);
extern int spscarab_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: spscarab_update
 * EN v1.0 Address: 0x801E8EE0
 * EN v1.0 Size: 588b
 */

/*
 * --INFO--
 *
 * Function: spscarab_init
 * EN v1.0 Address: 0x801E912C
 * EN v1.0 Size: 500b
 */

/*
 * --INFO--
 *
 * Function: spscarab_release
 * EN v1.0 Address: 0x801E9320
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spscarab_initialise
 * EN v1.0 Address: 0x801E9324
 * EN v1.0 Size: 4b
 */

ObjectDescriptor gSPScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spscarab_initialise,
    (ObjectDescriptorCallback)spscarab_release,
    0,
    (ObjectDescriptorCallback)spscarab_init,
    (ObjectDescriptorCallback)spscarab_update,
    (ObjectDescriptorCallback)spscarab_hitDetect,
    (ObjectDescriptorCallback)spscarab_render,
    (ObjectDescriptorCallback)spscarab_free,
    (ObjectDescriptorCallback)spscarab_getObjectTypeId,
    spscarab_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: spdrape_getExtraSize
 * EN v1.0 Address: 0x801E9328
 * EN v1.0 Size: 8b
 */
int spdrape_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: spdrape_getObjectTypeId
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */
int spdrape_getObjectTypeId(void);

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */
void spdrape_free(void);

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */
void spdrape_render(void);

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */
void spdrape_hitDetect(void);

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
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Camera_GetCurrentViewSlot(void);
extern f32 lbl_803DC0B0;
extern f32 lbl_803DC0B4;
extern byte framesThisStep;
extern f32 lbl_803E5AA0;
extern f32 lbl_803E5AA4;
extern f32 lbl_803E5AA8;
extern f32 lbl_803E5AAC;
extern f32 lbl_803E5AB0;
extern f32 lbl_803E5AB4;
extern f32 lbl_803E5AB8;
extern f32 lbl_803E5ABC;

void spdrape_update(int obj);


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
void spdrape_release(void);

void spdrape_initialise(void);

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

void spdrape_init(int* obj, u8* def);

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
void fn_801E991C(int p1, char* table);
#pragma opt_common_subs reset
