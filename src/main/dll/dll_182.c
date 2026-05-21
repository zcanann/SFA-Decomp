#include "ghidra_import.h"
#include "main/dll/dll_182.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f8();

extern f64 DOUBLE_803e4bc0;
extern f32 lbl_803E4B98;
extern f32 lbl_803E4B9C;
extern f32 lbl_803E4BA0;
extern f32 lbl_803E4BA4;
extern f32 lbl_803E4BA8;
extern f32 lbl_803E4BAC;
extern f32 lbl_803E4BB0;
extern f32 lbl_803E4BB4;
extern f32 lbl_803E4BB8;
extern f32 lbl_803E4BBC;

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

/*
 * --INFO--
 *
 * Function: FUN_80191f54
 * EN v1.0 Address: 0x80191F54
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801920F0
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80191f54(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void* mapGetBlock(int idx);
extern int* getTablesBinEntry(int id);
extern void* getLoadedTexture(int id);
extern void* fn_8006070C(void* block, int idx);
extern void fn_80056BBC(int slot, int a, int b, int c, int d, int e, int f, int g, int h);
extern int fn_80056BF4(int a, int b, int c, int d, int e, int f, int g, int h);

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
                            fn_80056BBC(
                                (s32)*(u8*)((char*)entry + 0x2a),
                                (s32)*(s8*)((char*)state + 0x11),
                                (s32)*(s8*)((char*)state + 0x12),
                                t1, t2,
                                (s32)*(s8*)((char*)state + 0x13),
                                (s32)*(s8*)((char*)state + 0x14),
                                t1, t2);
                        }
                    } else {
                        fn_80056BBC(
                            (s32)*(u8*)((char*)entry + 0x2a),
                            (s32)*(s8*)((char*)state + 0x11),
                            (s32)*(s8*)((char*)state + 0x12),
                            t1, t2,
                            (s32)*(s8*)((char*)state + 0x13),
                            (s32)*(s8*)((char*)state + 0x14),
                            t1, t2);
                    }
                } else {
                    *(u8*)((char*)entry + 0x2a) = (u8)fn_80056BF4(
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

/*
 * --INFO--
 *
 * Function: FUN_80191f74
 * EN v1.0 Address: 0x80191F74
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x80192118
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80191f74(int param_1)
{
  undefined auStack_18 [12];
  float local_c;
  float local_8;
  float local_4;
  
  if (*(short *)(param_1 + 0x46) == 0x79) {
    local_c = lbl_803E4B9C;
    local_8 = lbl_803E4BA0;
    local_4 = lbl_803E4B9C;
    FUN_800810f8((double)lbl_803E4BA4,(double)lbl_803E4BA8,(double)lbl_803E4BA8,
                 (double)lbl_803E4BAC,param_1,5,5,2,0x19,(int)auStack_18,0);
  }
  else if (*(short *)(param_1 + 0x46) == 0x748) {
    local_c = lbl_803E4B9C;
    local_8 = lbl_803E4BB0;
    local_4 = lbl_803E4B9C;
    FUN_800810f8((double)lbl_803E4BB4,(double)lbl_803E4BB8,(double)lbl_803E4BB8,
                 (double)lbl_803E4BAC,param_1,5,5,2,5,(int)auStack_18,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80192000
 * EN v1.0 Address: 0x80192000
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801921CC
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192000(short *param_1,int param_2)
{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e4bc0) /
         lbl_803E4BBC;
    if (*(float *)(param_1 + 4) == lbl_803E4B9C) {
      *(float *)(param_1 + 4) = lbl_803E4B98;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801920b8
 * EN v1.0 Address: 0x801920B8
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x80192298
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801920b8(int param_1)
{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((((*(byte *)(puVar4 + 5) >> 5 & 1) == 0) &&
      (uVar1 = GameBit_Get((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) &&
     ((*(byte *)(puVar4 + 5) >> 6 & 1) == 0)) {
    *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xdf | 0x20;
    puVar4[4] = 0;
  }
  if (((*(byte *)(puVar4 + 5) >> 5 & 1) != 0) &&
     (puVar2 = (uint *)FUN_80039520(param_1,*puVar4), puVar2 != (uint *)0x0)) {
    puVar4[4] = puVar4[4] + (uint)*(byte *)(puVar4 + 1);
    if ((int)puVar4[4] < 0) {
      puVar4[4] = 0;
    }
    else if ((int)puVar4[2] < (int)puVar4[4]) {
      uVar1 = (uint)*(short *)(iVar3 + 0x1e);
      if (uVar1 == 0xffffffff) {
        puVar4[4] = puVar4[3];
      }
      else {
        GameBit_Set(uVar1,1);
        *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xdf;
        *(byte *)(puVar4 + 5) = *(byte *)(puVar4 + 5) & 0xbf | 0x40;
        puVar4[4] = puVar4[2];
      }
    }
    *puVar2 = puVar4[4];
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void texscroll2_free(void) {}
void texscroll2_hitDetect(void) {}
void texscroll2_release(void) {}
void texscroll2_initialise(void) {}
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
