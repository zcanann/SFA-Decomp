/* DLL 0x801E991C - SPScarab [801E991C-...) */
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/dll/shwgpipe_struct.h"
#include "main/camera.h"
#include "main/sky_state.h"
#include "main/sfa_extern_decls.h"


extern void spscarab_free(int x);



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

volatile ShWGPipe GXWGFifo : (0xCC008000);

static inline void shPos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void shColor4u8(u8 r, u8 g, u8 b, u8 a)
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
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXSetCullMode(int mode);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXSetCurrentMtx(u32 id);
extern void GXBegin(int prim, int fmt, int n);

#define GX_BM_BLEND 1
#define GX_BL_SRCALPHA 4
#define GX_BL_INVSRCALPHA 5
#define GX_LO_NOOP 5
#define GX_ALWAYS 7
#define GX_AOP_AND 0
#define GX_CULL_NONE 0
#define GX_VA_POS 9
#define GX_VA_CLR0 11
#define GX_VA_TEX0 13
#define GX_DIRECT 1
#define GX_QUADS 0x80
#define GX_VTXFMT2 2

extern int lbl_803DDC60;
extern ShColor lbl_803E5AE4;
extern const f32 lbl_803E5AE8;
extern const f32 lbl_803E5AEC;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

#pragma opt_common_subs off
void fn_801E991C(int p1, char* table)
{
    u8 r;
    u8 g;
    u8 b;
    ShColor color;
    f32* verts;
    char* p;
    int i;
    int j;

    color = lbl_803E5AE4;
    selectTexture(lbl_803DDC60, 0);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    textRenderSetupFn_80079804();
    GXSetTevColor(2, color);
    gxSetZMode_(1, 3, 0);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    getAmbientColor(0, &r, &g, &b);
    i = 0;
    p = table;
    for (; i < 9; i++)
    {
        if (((*(u8*)(p + 0x4ce) & 1) != 0) && (*(s16*)(p + 0x4cc) >= 4))
        {
            j = 0;
            verts = *(f32**)(p + 0x4c8);
            while (j < *(s16*)(p + 0x4cc) - 2)
            {
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                shPos3f32(verts[0] - playerMapOffsetX, verts[0 + 1], verts[0 + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0xc));
                shTexCoord2f32(lbl_803E5AE8, lbl_803E5AE8);
                shPos3f32(verts[4] - playerMapOffsetX, verts[4 + 1], verts[4 + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0x1c));
                shTexCoord2f32(lbl_803E5AEC, lbl_803E5AE8);
                shPos3f32(verts[0xc] - playerMapOffsetX, verts[0xc + 1], verts[0xc + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0x3c));
                shTexCoord2f32(lbl_803E5AEC, lbl_803E5AE8);
                shPos3f32(verts[8] - playerMapOffsetX, verts[8 + 1], verts[8 + 2] - playerMapOffsetZ);
                shColor4u8(*(u8*)&r, *(u8*)&g, *(u8*)&b, (u8) * (s16*)((char*)verts + 0x2c));
                shTexCoord2f32(lbl_803E5AE8, lbl_803E5AE8);
                verts += 8;
                j += 2;
            }
        }
        p += 8;
    }
}
#pragma opt_common_subs reset
