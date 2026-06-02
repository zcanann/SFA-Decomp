#include "ghidra_import.h"
#include "main/dll/mmp_moonrock.h"

extern uint GameBit_Get(int eventId);

#pragma scheduling off
#pragma peephole off
void texscroll2_setScale(int obj, s8 scale)
{
  s8 *state;

  state = *(s8 **)(obj + 0xb8);
  if (state[0x12] == scale) {
    return;
  }
  state[0x12] = scale;
  state[0x10] = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void* mapGetBlock(int idx);
extern int* getTablesBinEntry(int id);
extern void* getLoadedTexture(int id);
extern void* fn_8006070C(void* block, int idx);
extern void mapTextureScrollSetStep(int slot, int xStep, int yStep, int texWidthFixed, int texHeightFixed, int unusedXStep, int unusedYStep, int unusedWidthFixed, int unusedHeightFixed);
extern int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed, int unusedXStep, int unusedYStep, int unusedWidthFixed, int unusedHeightFixed);

#pragma scheduling off
#pragma peephole off
void fn_80191F54(int obj, int* state)
{
    int* def;
    void* block;
    int* tables;
    void* tex;
    int i, j;
    void* sub;
    void* entry;
    int t1, t2;

    def = *(int**)((char*)obj + 0x4c);
    block = mapGetBlock(objPosToMapBlockIdx(
        *(f32*)((char*)obj + 0xc),
        *(f32*)((char*)obj + 0x10),
        *(f32*)((char*)obj + 0x14)));
    if (block == NULL) {
        *(u8*)((char*)state + 0x10) = 1;
        return;
    }
    tables = (int*)getTablesBinEntry(0xe);
    if (tables == NULL) return;
    tex = getLoadedTexture(-tables[(s32)*(s16*)((char*)def + 0x18)]);
    if (tex == NULL) return;

    for (i = 0; i < (s32)*(u8*)((char*)block + 0xa2); i++) {
        sub = fn_8006070C(block, i);
        entry = sub;
        for (j = 0; j < (s32)*(u8*)((char*)sub + 0x41); j++) {
            if (*(void**)((char*)entry + 0x24) == tex) {
                t1 = (s32)(u32)*(u16*)((char*)tex + 0xa) << 6;
                t2 = (s32)(u32)*(u16*)((char*)tex + 0xc) << 6;
                if (*(u8*)((char*)entry + 0x2a) != 0xff) {
                    int v = *(int*)((char*)*(int**)((char*)obj + 0x4c) + 0x14);
                    if (v == 0x49b2f || v == 0x49b67) {
                        if (GameBit_Get(*(int*)((char*)state + 0x8)) != 0) {
                            mapTextureScrollSetStep(
                                (s32)*(u8*)((char*)entry + 0x2a),
                                (s32)*(s8*)((char*)state + 0x11),
                                (s32)*(s8*)((char*)state + 0x12),
                                t1, t2,
                                (s32)*(s8*)((char*)state + 0x13),
                                (s32)*(s8*)((char*)state + 0x14),
                                t1, t2);
                        }
                    } else {
                        mapTextureScrollSetStep(
                            (s32)*(u8*)((char*)entry + 0x2a),
                            (s32)*(s8*)((char*)state + 0x11),
                            (s32)*(s8*)((char*)state + 0x12),
                            t1, t2,
                            (s32)*(s8*)((char*)state + 0x13),
                            (s32)*(s8*)((char*)state + 0x14),
                            t1, t2);
                    }
                } else {
                    *(u8*)((char*)entry + 0x2a) = (u8)mapTextureScrollAcquire(
                        (s32)*(s8*)((char*)state + 0x11),
                        (s32)*(s8*)((char*)state + 0x12),
                        t1, t2,
                        (s32)*(s8*)((char*)state + 0x13),
                        (s32)*(s8*)((char*)state + 0x14),
                        t1, t2);
                }
            }
            entry = (void*)((char*)entry + 8);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void texscroll2_free(void) {}
void texscroll2_hitDetect(void) {}
void texscroll2_release(void) {}
void texscroll2_initialise(void) {}

extern uint GameBit_Get(int eventId);

#pragma scheduling off
#pragma peephole off
void texscroll2_update(int *obj) {
    u8 *sub;
    int *block;

    sub = *(u8**)((char*)obj + 0xb8);
    block = (int*)mapGetBlock(objPosToMapBlockIdx(*(f32*)((char*)obj + 0xc), *(f32*)((char*)obj + 0x10), *(f32*)((char*)obj + 0x14)));
    {
        int mapId = *(int*)(*(int*)((char*)obj + 0x4c) + 0x14);
        if (mapId == 0x49b2f || mapId == 0x49b67) {
            if (block != NULL) {
                if (GameBit_Get(*(int*)(sub + 8)) != *(uint*)(sub + 0xc) && sub[0x10] == 0) {
                    fn_80191F54((int)obj, (int*)sub);
                    sub[0x10] = 0;
                }
            }
        }
    }
    *(int*)(sub + 0xc) = GameBit_Get(*(int*)(sub + 8));
    if (block == NULL) {
        sub[0x10] = 1;
    } else {
        if (sub[0x10] != 0) {
            fn_80191F54((int)obj, (int*)sub);
            sub[0x10] = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
void texscroll_free(void) {}
void texscroll_hitDetect(void) {}
void texscroll_update(void) {}
void texscroll_release(void) {}
void texscroll_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int texscroll2_getExtraSize(void) { return 0x18; }
int texscroll2_getObjectTypeId(void) { return 0x0; }
int texscroll_getExtraSize(void) { return 0x1c; }
int texscroll_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void waveanimator_modelMtxFn(int obj, int a, int b, int c) {
    int *state = *(int **)((char *)obj + 0xB8);
    u32 v;
    v = (u32)*(u8 *)((char *)state + 0x34) | 4;
    *(u8 *)((char *)state + 0x34) = (u8)v;
    *(u8 *)((char *)state + 0x36) = (u8)a;
    *(u8 *)((char *)state + 0x37) = (u8)b;
    *(u8 *)((char *)state + 0x38) = (u8)c;
}

extern void fn_80191F54(int obj, int *state);
void texscroll2_init(int obj, u8 *def, int flag) {
    int *state = *(int **)((char *)obj + 0xB8);
    *(u8 *)((char *)state + 0x11) = def[0x1E];
    *(u8 *)((char *)state + 0x12) = def[0x1F];
    *(u8 *)((char *)state + 0x13) = def[0x1C];
    *(u8 *)((char *)state + 0x14) = def[0x1D];
    if (flag == 0) {
        fn_80191F54(obj, state);
    }
    *(int *)((char *)state + 8) = (int)*(s16 *)((char *)def + 0x1A);
    *(int *)((char *)state + 0xC) = -1;
}

void texscroll_init(int obj, s8 *def, int flag) {
    s16 *state = *(s16 **)((char *)obj + 0xB8);
    if (state == NULL) return;
    *(s16 *)((char *)state + 2) = 1;
    *(s16 *)((char *)state + 4) = (s16)(s32)def[0x1E];
    *(s16 *)((char *)state + 6) = (s16)(s32)def[0x1F];
    *(int *)((char *)state + 0xC) = 0;
    *(u8 *)((char *)state + 0x18) = 0;
    *(s16 *)((char *)state + 0x14) = *(s16 *)((char *)def + 0x1A);
    if (flag == 0) {
        *(s16 *)((char *)state + 8) = 0;
        *(s16 *)((char *)state + 0xA) = 0;
    }
    *(s16 *)((char *)state + 2) = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3F30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F38;
#pragma peephole off
void texscroll2_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3F30); }
void texscroll_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3F38); }
#pragma peephole reset
