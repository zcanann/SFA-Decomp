/* === moved from main/dll/DR/DRCloudball.c [801E9328-801E9344) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/dll/sh_types.h"







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

/*
 * --INFO--
 *
 * Function: spdrape_getObjectTypeId
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */

#include "main/objanim_internal.h"
#include "main/game_object.h"
#include "main/dll/DR/DRsimplehuman.h"









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


/* Trivial 4b 0-arg blr leaves. */









/* 8b "li r3, N; blr" returners. */





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
