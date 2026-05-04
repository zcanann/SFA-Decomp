#include "ghidra_import.h"
#include "main/dll/dll_182.h"

extern uint FUN_80017690();
extern undefined4 FUN_80017698();
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
      (uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) &&
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
        FUN_80017698(uVar1,1);
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
int texscroll2_func08(void) { return 0x0; }
int texscroll_getExtraSize(void) { return 0x1c; }
int texscroll_func08(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E3F30;
extern void fn_8003B8F4(f32);
extern f32 lbl_803E3F38;
#pragma peephole off
void texscroll2_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3F30); }
void texscroll_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3F38); }
#pragma peephole reset
