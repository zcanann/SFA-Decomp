#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"

volatile PPCWGPipe GXWGFifo : (0xCC008000);

static inline void GXPos3f32(f32 x, f32 y, f32 z) {
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void GXTex2f32(f32 s, f32 t) {
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

extern u8 *Camera_GetCurrentViewSlot(void);
extern void fn_8008DAE8(int obj);
extern u8 *Obj_GetActiveModel(int obj);
extern void fn_800412B8(int a, int b, int c);
extern void objRender(int a, int b, int c, int d, int obj, int e);
extern int shouldDrawClouds(void);
extern u8 isOvercast(void);
extern void fn_80060490(int *a, int *b, int *c, int *d);
extern void GXGetScissor(int *x, int *y, int *w, int *h);
extern void GXSetScissor(int x, int y, int w, int h);
extern void fn_8003BB7C(int a);
extern void GXSetColorUpdate(int enable);
extern f32 fn_8008ED88(void);
extern void fn_8008EDE8(f32 *pos);
extern void Camera_RebuildProjectionMatrix(void);
extern void textureSetupFn_800799c0(void);
extern void gxTextureFn_800794e0(void);
extern void textRenderSetupFn_80079804(void);
extern void gxBlendFn_800789ac(void);
extern void PSMTXMultVec(void *m, f32 *src, f32 *dst);
extern void PSMTXTrans(f32 *m, f32 x, f32 y, f32 z);
extern int fn_8008912C(void);
extern void selectTexture(int tex, int a);
extern void _gxSetTevColor2(int r, int g, int b, int a);
extern int getHudHiddenFrameCount(void);

extern f32 lbl_803DD1E0;
extern f32 lbl_803DD1E4;
extern f32 lbl_803DD1E8;
extern u8 lbl_803DD1EC;
extern volatile f32 lbl_803DB780;
extern const f32 lbl_803DF2B4;
extern const f32 lbl_803DF2C0;
extern const f32 lbl_803DF2C4;
extern const f32 lbl_803DF2C8;
extern const f32 lbl_803DF2CC;
extern const f32 lbl_803DF2D0;
extern const f32 lbl_803DF2D4;
extern const f32 lbl_803DF2D8;

void cloudaction_func08_nop(void) {}

void cloudaction_func09_nop(void) {}

#pragma scheduling off
#pragma peephole off
void cloudaction_free(void) {
    if (*(void **)lbl_8039AB28 != NULL) {
        Obj_FreeObject(*(int *)lbl_8039AB28);
        *(int *)lbl_8039AB28 = 0;
    }
    *(int *)(lbl_8039AB28 + 0xc) = 0;
    if (*(void **)(lbl_8039AB28 + 4) != NULL) {
        Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
        *(int *)(lbl_8039AB28 + 4) = 0;
    }
    *(int *)(lbl_8039AB28 + 0x10) = 0;
    if (*(void **)(lbl_8039AB28 + 8) != NULL) {
        Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
        *(int *)(lbl_8039AB28 + 8) = 0;
    }
    *(int *)(lbl_8039AB28 + 0x14) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void renderClouds(int a, int b, int c, int d) {
    u8 p0;
    u8 p1;
    u8 p2;
    u8 p3;
    u8 p4;
    u8 p5;
    int s0;
    int s1;
    int s2;
    int s3;
    int t0;
    int t1;
    int t2;
    int t3;
    f32 pos[3];
    f32 mtx[12];
    u8 *view;
    u8 *model;
    void *viewMtx;
    f32 cloudT;
    f32 v;

    view = Camera_GetCurrentViewSlot();
    (*(void (**)(u8 *, u8 *, u8 *, u8 *, u8 *, u8 *))(*(char **)gSHthorntailAnimationInterface + 0x40))(
        &p0, &p1, &p2, &p3, &p4, &p5);

    if (*(void **)&lbl_803DD1F0 != NULL) {
        fn_8008DAE8(lbl_803DD1F0);
        model = Obj_GetActiveModel(lbl_803DD1F0);
        *(u16 *)(model + 0x18) = *(u16 *)(model + 0x18) & ~8;
        *(u8 *)(lbl_803DD1F0 + 0x37) = 0xff;
        v = *(f32 *)(view + 0xc);
        *(f32 *)(lbl_803DD1F0 + 0x18) = v;
        *(f32 *)(lbl_803DD1F0 + 0xc) = v;
        v = *(f32 *)(view + 0x10);
        *(f32 *)(lbl_803DD1F0 + 0x1c) = v;
        *(f32 *)(lbl_803DD1F0 + 0x10) = v;
        v = *(f32 *)(view + 0x14);
        *(f32 *)(lbl_803DD1F0 + 0x20) = v;
        *(f32 *)(lbl_803DD1F0 + 0x14) = v;
        fn_800412B8(p0, p1, p2);
        objRender(a, b, c, d, lbl_803DD1F0, 1);
        return;
    }

    if (shouldDrawClouds() == 0) {
        return;
    }

    if (*(void **)(lbl_8039AB28 + 4) != NULL) {
        model = Obj_GetActiveModel(*(int *)(lbl_8039AB28 + 4));
        *(u16 *)(model + 0x18) = *(u16 *)(model + 0x18) & ~8;
        *(u8 *)(*(int *)(lbl_8039AB28 + 4) + 0x37) = 0xff;
        if ((u32)lbl_803DD1EC != 0) {
            *(f32 *)(*(int *)(lbl_8039AB28 + 4) + 0xc) = lbl_803DD1E8;
            *(f32 *)(*(int *)(lbl_8039AB28 + 4) + 0x10) = lbl_803DF2C0 + lbl_803DD1E4;
            *(f32 *)(*(int *)(lbl_8039AB28 + 4) + 0x14) = lbl_803DD1E0;
        } else {
            fn_8008DAE8(*(int *)(lbl_8039AB28 + 4));
            *(f32 *)(*(int *)(lbl_8039AB28 + 4) + 0xc) = *(f32 *)(view + 0xc);
            *(f32 *)(*(int *)(lbl_8039AB28 + 4) + 0x10) = *(f32 *)(view + 0x10);
            *(f32 *)(*(int *)(lbl_8039AB28 + 4) + 0x14) = *(f32 *)(view + 0x14);
        }
        fn_800412B8(p0, p1, p2);
        objRender(a, b, c, d, *(int *)(lbl_8039AB28 + 4), 1);
    }

    if (*(void **)lbl_8039AB28 != NULL) {
        if (isOvercast()) {
            fn_8008DAE8(*(int *)lbl_8039AB28);
        }
        model = Obj_GetActiveModel(*(int *)lbl_8039AB28);
        *(u16 *)(model + 0x18) = *(u16 *)(model + 0x18) & ~8;
        *(u8 *)(*(int *)lbl_8039AB28 + 0x37) = 0xff;
        v = *(f32 *)(view + 0xc);
        *(f32 *)(*(int *)lbl_8039AB28 + 0x18) = v;
        *(f32 *)(*(int *)lbl_8039AB28 + 0xc) = v;
        v = lbl_803DF2C4 + *(f32 *)(view + 0x10);
        *(f32 *)(*(int *)lbl_8039AB28 + 0x1c) = v;
        *(f32 *)(*(int *)lbl_8039AB28 + 0x10) = v;
        v = *(f32 *)(view + 0x14);
        *(f32 *)(*(int *)lbl_8039AB28 + 0x20) = v;
        *(f32 *)(*(int *)lbl_8039AB28 + 0x14) = v;
        *(u16 *)(*(int *)lbl_8039AB28 + 2) = 0;
        fn_800412B8(p0, p1, p2);
        objRender(a, b, c, d, *(int *)lbl_8039AB28, 1);

        fn_80060490(&s0, &s1, &s2, &s3);
        if (s2 > 0 && s3 > 0) {
            GXGetScissor(&t0, &t1, &t2, &t3);
            GXSetScissor(s0, s1, s2, s3);
            *(u16 *)(*(int *)model + 2) = *(u16 *)(*(int *)model + 2) | 0x2000;
            fn_8003BB7C(0x80);
            GXSetColorUpdate(0);
            objRender(a, b, c, d, *(int *)lbl_8039AB28, 1);
            *(u16 *)(*(int *)model + 2) = *(u16 *)(*(int *)model + 2) & ~0x2000;
            fn_8003BB7C(0);
            GXSetColorUpdate(1);
            GXSetScissor(t0, t1, t2, t3);
        }
    }

    cloudT = fn_8008ED88();
    if (cloudT > lbl_803DF2B4) {
        fn_8008EDE8(pos);
        pos[0] -= playerMapOffsetX;
        pos[2] -= playerMapOffsetZ;
        viewMtx = Camera_GetViewMatrix();
        GXSetCullMode(0);
        Camera_RebuildProjectionMatrix();
        GXClearVtxDesc();
        GXSetVtxDesc(9, 1);
        GXSetVtxDesc(0xd, 1);
        textureSetupFn_800799c0();
        gxTextureFn_800794e0();
        textRenderSetupFn_80079804();
        gxBlendFn_800789ac();
        PSMTXMultVec(viewMtx, pos, pos);
        PSMTXTrans(mtx, pos[0], pos[1], pos[2]);
        GXLoadPosMtxImm(mtx, 0);
        GXSetCurrentMtx(0);
        selectTexture(fn_8008912C(), 0);
        if (cloudT >= lbl_803DF2C8) {
            _gxSetTevColor2(0x80, 0x80, 0xff, 0xff);
        } else {
            _gxSetTevColor2(0x80, 0x80, 0xff, (int)(lbl_803DF2CC * (lbl_803DF2D0 * cloudT)));
        }
        if (getHudHiddenFrameCount() == 0) {
            *(f32 *)&lbl_803DB780 = (f32)randomGetRange(0x1f40, 0x2ee0);
        }
        GXBegin(0x80, 2, 4);
        v = -lbl_803DB780;
        GXPos3f32(v, v, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2B4, lbl_803DF2B4);
        GXPos3f32(lbl_803DB780, -lbl_803DB780, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2D4, lbl_803DF2B4);
        GXPos3f32(lbl_803DB780, lbl_803DB780, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2D4, lbl_803DF2D4);
        v = lbl_803DB780;
        GXPos3f32(-v, v, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2B4, lbl_803DF2D4);
    }

    if (*(void **)(lbl_8039AB28 + 8) != NULL) {
        model = Obj_GetActiveModel(*(int *)(lbl_8039AB28 + 8));
        *(u16 *)(model + 0x18) = *(u16 *)(model + 0x18) & ~8;
        *(u8 *)(*(int *)(lbl_8039AB28 + 8) + 0x37) = 0xff;
        if ((u32)lbl_803DD1EC != 0) {
            *(f32 *)(*(int *)(lbl_8039AB28 + 8) + 0xc) = lbl_803DD1E8;
            *(f32 *)(*(int *)(lbl_8039AB28 + 8) + 0x10) = lbl_803DD1E4 - lbl_803DF2D8;
            *(f32 *)(*(int *)(lbl_8039AB28 + 8) + 0x14) = lbl_803DD1E0;
        } else {
            fn_8008DAE8(*(int *)(lbl_8039AB28 + 8));
            *(f32 *)(*(int *)(lbl_8039AB28 + 8) + 0xc) = *(f32 *)(view + 0xc);
            *(f32 *)(*(int *)(lbl_8039AB28 + 8) + 0x10) = *(f32 *)(view + 0x10);
            *(f32 *)(*(int *)(lbl_8039AB28 + 8) + 0x14) = *(f32 *)(view + 0x14);
        }
        objRender(a, b, c, d, *(int *)(lbl_8039AB28 + 8), 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cloudaction_func05(void) {
    char *tex;
    if (*(void **)lbl_8039AB28 != NULL) {
        tex = (char *)objFindTexture(*(int *)lbl_8039AB28, 0, 0);
        if (tex != NULL) {
            *(s16 *)(tex + 8) -= lbl_8039AB28[0x18];
            if (*(s16 *)(tex + 8) < -0x2710) {
                *(s16 *)(tex + 8) += 0x2710;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cloudaction_onMapSetup(void) {
    memset(lbl_8039AB28, 0, 0x1c);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cloudaction_update(int p1, int p2, u8 *state, int p4, int val) {
    CloudEnvTbl *tbl = (CloudEnvTbl *)lbl_8030F7B0;

    saveGameGetEnvState();
    if (state == NULL) {
        return;
    }
    if ((state[0x58] & 2) == 0) {
        return;
    }
    *(s16 *)((char *)tbl + 0xa) = (s16)((s16)*(u16 *)(state + 0x24) - 1);
    if ((state[0x59] & 1) == 0) {
        return;
    }
    lbl_803DB618[0] = lbl_803DB618[1];
    lbl_803DB618[1] = (u16)val;
    lbl_8039AB28[0x18] = (int)(*(f32 *)(state + 8) / lbl_803DF2DC);
    lbl_8039AB28[0x19] = 0;
    if ((state[0x59] & 4) != 0) {
        lbl_8039AB28[0x1a] = 0;
    } else {
        lbl_8039AB28[0x1a] = 1;
    }
    if (state[0x5d] != 0) {
        if (state[0x5d] < 5) {
            if (*(int *)(lbl_8039AB28 + 0xc) != tbl->a[state[0x5d]]) {
                if (*(void **)lbl_8039AB28 != NULL) {
                    Obj_FreeObject(*(int *)lbl_8039AB28);
                }
                *(int *)lbl_8039AB28 = (int)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->a[state[0x5d]]), 4, -1, -1, 0);
                *(int *)(lbl_8039AB28 + 0xc) = tbl->a[state[0x5d]];
            }
        }
    } else {
        if (*(void **)lbl_8039AB28 != NULL) {
            Obj_FreeObject(*(int *)lbl_8039AB28);
            *(int *)lbl_8039AB28 = 0;
        }
        *(int *)(lbl_8039AB28 + 0xc) = 0;
    }
    if (state[0x5b] != 0) {
        if (state[0x5b] < 4) {
            if (*(int *)(lbl_8039AB28 + 0x10) != tbl->b[state[0x5b]]) {
                if (*(void **)(lbl_8039AB28 + 4) != NULL) {
                    Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
                }
                *(int *)(lbl_8039AB28 + 4) = (int)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->b[state[0x5b]]), 4, -1, -1, 0);
                *(int *)(lbl_8039AB28 + 0x10) = tbl->b[state[0x5b]];
            }
        }
    } else {
        if (*(void **)(lbl_8039AB28 + 4) != NULL) {
            Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
            *(int *)(lbl_8039AB28 + 4) = 0;
        }
        *(int *)(lbl_8039AB28 + 0x10) = 0;
    }
    if (state[0x5a] != 0) {
        if (state[0x5a] < 5) {
            if (*(int *)(lbl_8039AB28 + 0x14) != tbl->c[state[0x5a]]) {
                if (*(void **)(lbl_8039AB28 + 8) != NULL) {
                    Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
                }
                *(int *)(lbl_8039AB28 + 8) = (int)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->c[state[0x5a]]), 4, -1, -1, 0);
                *(int *)(lbl_8039AB28 + 0x14) = tbl->c[state[0x5a]];
            }
        }
    } else {
        if (*(void **)(lbl_8039AB28 + 8) != NULL) {
            Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
            *(int *)(lbl_8039AB28 + 8) = 0;
        }
        *(int *)(lbl_8039AB28 + 0x14) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

void cloudaction_release(void) {}

#pragma scheduling off
#pragma peephole off
void cloudaction_initialise(void) {
    lbl_803DB618[0] = -1;
    lbl_803DB618[1] = -1;
    lbl_803DD1F0 = 0;
}
#pragma peephole reset
#pragma scheduling reset

