#include "ghidra_import.h"
#include "main/dll/dll_14C.h"

extern uint FUN_80017690();
extern uint FUN_80017760();
extern undefined4 FUN_80017a78();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();

extern f64 DOUBLE_803e44b8;
extern f64 DOUBLE_803e44d8;
extern f32 lbl_803E4460;
extern f32 lbl_803E446C;
extern f32 lbl_803E4474;
extern f32 lbl_803E44C0;
extern f32 lbl_803E44C4;
extern f32 lbl_803E44C8;
extern f32 lbl_803E44CC;
extern f32 lbl_803E44D0;

/*
 * --INFO--
 *
 * Function: FUN_8017ec94
 * EN v1.0 Address: 0x8017EC94
 * EN v1.0 Size: 1048b
 * EN v1.1 Address: 0x8017EEBC
 * EN v1.1 Size: 704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ec94(undefined2 *param_1,int param_2)
{
  float fVar1;
  double dVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  
  puVar6 = *(undefined4 **)(param_1 + 0x5c);
  *puVar6 = *(undefined4 *)(param_2 + 0x18);
  dVar2 = DOUBLE_803e44d8;
  puVar6[1] = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1c)) -
                     DOUBLE_803e44d8);
  puVar6[2] = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1e)) - dVar2);
  fVar1 = lbl_803E44C0;
  puVar6[4] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - dVar2) /
              lbl_803E44C0;
  puVar6[5] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - dVar2) / fVar1
              + (float)puVar6[4];
  puVar6[6] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x22)) - dVar2) / fVar1
              + (float)puVar6[5];
  puVar6[7] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x23)) - dVar2) / fVar1
              + (float)puVar6[6];
  puVar6[8] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - dVar2) / fVar1;
  puVar6[10] = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x25) ^ 0x80000000) -
                      DOUBLE_803e44b8) / fVar1;
  puVar6[10] = (float)puVar6[10] * lbl_803E4474;
  puVar6[9] = lbl_803E4460;
  *(undefined2 *)(puVar6 + 0xe) = 0;
  fVar1 = lbl_803E446C;
  puVar6[0xf] = lbl_803E446C;
  puVar6[0x10] = lbl_803E44C4;
  puVar6[0x11] = fVar1;
  fVar1 = (float)puVar6[1] * (float)puVar6[6] * (float)puVar6[1] * (float)puVar6[6];
  fVar1 = fVar1 * fVar1;
  puVar6[0x15] = fVar1 * fVar1 * lbl_803E44C8;
  uVar3 = FUN_80017760(0xffff8000,0x7fff);
  *param_1 = (short)uVar3;
  *(float *)(param_1 + 4) = lbl_803E44CC;
  FUN_80017a78((int)param_1,0);
  if (((int)*(short *)(param_2 + 0x26) == 0xffffffff) ||
     (uVar3 = FUN_80017690((int)*(short *)(param_2 + 0x26)), uVar3 == 0)) {
    fVar1 = (float)puVar6[2] / (float)puVar6[1];
    if ((float)puVar6[4] <= fVar1) {
      if ((float)puVar6[5] <= fVar1) {
        if ((float)puVar6[6] <= fVar1) {
          iVar5 = *(int *)(param_1 + 0x5c);
          puVar4 = (undefined4 *)FUN_80039520((int)param_1,0);
          *puVar4 = 0;
          *(float *)(iVar5 + 0x24) = lbl_803E4460;
          *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
          FUN_80017a78((int)param_1,1);
          *(undefined *)((int)puVar6 + 0x3a) = 3;
        }
        else {
          *(undefined *)((int)puVar6 + 0x3a) = 2;
        }
      }
      else {
        *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
        *(undefined *)((int)puVar6 + 0x3a) = 1;
      }
    }
    else {
      *(undefined *)((int)puVar6 + 0x3a) = 0;
    }
  }
  else {
    puVar6[2] = lbl_803E44D0;
    *(undefined *)((int)puVar6 + 0x3a) = 6;
  }
  ObjMsg_AllocQueue((int)param_1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017f0ac
 * EN v1.0 Address: 0x8017F0AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017F17C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f0ac(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017f0d4
 * EN v1.0 Address: 0x8017F0D4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8017F1AC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f0d4(int param_1)
{
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_800400b0();
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_8017EF64(void) {}
void fn_8017EF68(void) {}
void fn_8017EF7C(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_8017EF6C(void) { return 0x8; }
int fn_8017EF74(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E3850;
extern void fn_8003B8F4(f32);
#pragma peephole off
void fn_8017EF80(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3850); }
#pragma peephole reset
