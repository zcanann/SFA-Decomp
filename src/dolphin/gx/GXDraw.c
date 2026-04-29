#include <dolphin/gx.h>

float cosf(float);
float sinf(float);

static struct {
    GXVtxDescList vcd[27];
    GXVtxAttrFmtList vat[27];
} lbl_803AEA38;

#define vcd lbl_803AEA38.vcd
#define vat lbl_803AEA38.vat

static inline void GetVertState(void) {
    GXGetVtxDescv(vcd);
    GXGetVtxAttrFmtv(GX_VTXFMT3, vat);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_NRM, GX_DIRECT);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_POS, GX_POS_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_NRM, GX_NRM_XYZ, GX_F32, 0);
}

static inline void RestoreVertState(void) {
    GXSetVtxDescv(vcd);
    GXSetVtxAttrFmtv(GX_VTXFMT3, vat);
}

void GXDrawTorus(f32 rc, u8 numc, u8 numt) {
    GXAttrType ttype;
    s32 i;
    s32 j;
    s32 k;
    f32 s;
    f32 t;
    f32 x;
    f32 y;
    f32 z;
    f32 twopi = 6.2831855f;
    f32 rt;

    rt = 1.0f - rc;
    GXGetVtxDesc(GX_VA_TEX0, &ttype);
    GetVertState();
    if (ttype != GX_NONE) {
        GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
        GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX0, GX_TEX_ST, GX_F32, 0);
    }
    for (i = 0; i < numc; i++) {
        GXBegin(GX_TRIANGLESTRIP, GX_VTXFMT3, (numt + 1) * 2);
        for (j = 0; j <= numt; j++) {
            for (k = 1; k >= 0; k--) {
                s = (i + k) % numc;
                t = j % numt;
                x = (rt - rc * cosf(s * twopi / numc)) * cosf(t * twopi / numt);
                y = (rt - rc * cosf(s * twopi / numc)) * sinf(t * twopi / numt);
                z = rc * sinf(s * twopi / numc);
                GXPosition3f32(x, y, z);
                x = -cosf(t * twopi / numt) * cosf(s * twopi / numc);
                y = -sinf(t * twopi / numt) * cosf(s * twopi / numc);
                z = sinf(s * twopi / numc);
                GXNormal3f32(x, y, z);
                if (ttype != GX_NONE) {
                    GXTexCoord2f32((i + k) / (f32)numc, j / (f32)numt);
                }
            }
        }
        GXEnd();
    }
    RestoreVertState();
}
