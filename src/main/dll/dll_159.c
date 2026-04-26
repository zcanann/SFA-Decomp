#include "ghidra_import.h"
#include "main/dll/dll_159.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_AddObject();

extern undefined4 DAT_803de740;
extern f64 DOUBLE_803e4648;
extern f64 DOUBLE_803e4660;
extern f32 FLOAT_803e4644;
extern f32 FLOAT_803e4650;
extern f32 FLOAT_803e4654;
extern f32 FLOAT_803e4658;
extern f32 FLOAT_803e465c;

/*
 * --INFO--
 *
 * Function: FUN_801833e4
 * EN v1.0 Address: 0x801833E4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x801835EC
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801833e4(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  ObjHits_DisableObject((int)param_1);
  ObjGroup_AddObject((int)param_1,0x10);
  if (*(short *)(param_2 + 0x1c) == 0) {
    *(undefined4 *)(iVar2 + 0x18) = 0;
  }
  else {
    *(int *)(iVar2 + 0x18) = *(short *)(param_2 + 0x1c) * 0x3c;
  }
  DAT_803de740 = FUN_80006b14(0x5b);
  uVar1 = FUN_80017760(0,100);
  *(short *)(iVar2 + 0xe) = (short)uVar1 + 300;
  *(char *)(iVar2 + 0x1f) = (char)*(undefined2 *)(param_2 + 0x1a);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(iVar2 + 0x1c) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(iVar2 + 0xc) = *(undefined2 *)(param_2 + 0x20);
  if (*(short *)(iVar2 + 0xc) == 0) {
    *(undefined2 *)(iVar2 + 0xc) = 0x14;
  }
  *(undefined2 *)(iVar2 + 0x12) = 800;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined *)(iVar2 + 0x1e) = *(undefined *)(param_2 + 0x19);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 10);
  uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1c));
  if (uVar1 != 0) {
    *(undefined4 *)(iVar2 + 0x14) = 1;
    ObjHits_DisableObject((int)param_1);
  }
  if (param_1[0x23] == 0x3cf) {
    *(undefined2 *)(iVar2 + 0x10) = 0x60;
  }
  else if (param_1[0x23] == 0x662) {
    *(undefined *)(iVar2 + 0x20) = 1;
    *(undefined2 *)(iVar2 + 0x10) = 0x37d;
  }
  else {
    *(undefined2 *)(iVar2 + 0x10) = 0x4a;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80183544
 * EN v1.0 Address: 0x80183544
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8018375C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80183544(int param_1)
{
  return (double)(FLOAT_803e4644 -
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x13)) -
                        DOUBLE_803e4648) /
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x28)) -
                        DOUBLE_803e4648));
}

/*
 * --INFO--
 *
 * Function: FUN_801835c4
 * EN v1.0 Address: 0x801835C4
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x801837A8
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801835c4(uint param_1,int param_2)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_80017a98();
  if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
    fVar1 = *(float *)(param_1 + 0x24);
    *(float *)(param_1 + 0x24) =
         -(float)((double)CONCAT44(0x43300000,
                                   (int)*(short *)(*(int *)(param_1 + 0x30) + 4) +
                                   (uint)*(ushort *)(param_2 + 0x20) ^ 0x80000000) - DOUBLE_803e4660
                 ) / *(float *)(param_2 + 0x1c);
    if (((((fVar1 <= FLOAT_803e4650) && (FLOAT_803e4650 <= *(float *)(param_1 + 0x24))) ||
         ((FLOAT_803e4650 <= fVar1 && (*(float *)(param_1 + 0x24) <= FLOAT_803e4650)))) &&
        ((((iVar4 = *(int *)(iVar4 + 0x14), iVar4 == 0x465d7 || (iVar4 - 0x465d5U < 2)) ||
          (iVar4 == 0x66)) || ((iVar4 == 0x465d0 || (iVar4 == 0x465d2)))))) &&
       ((dVar5 = (double)FUN_8001771c((float *)(iVar2 + 0x18),(float *)(param_1 + 0x18)),
        dVar5 < (double)FLOAT_803e4654 && (uVar3 = FUN_80017690(0xa71), uVar3 == 0)))) {
      FUN_80006824(param_1,0x313);
    }
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + *(float *)(param_1 + 0x24);
    fVar1 = FLOAT_803e4658 + *(float *)(param_2 + 0x24);
    if (*(float *)(param_1 + 0xc) <= fVar1) {
      fVar1 = *(float *)(param_2 + 0x24) - FLOAT_803e465c;
      if (*(float *)(param_1 + 0xc) < fVar1) {
        *(float *)(param_1 + 0xc) = fVar1;
      }
    }
    else {
      *(float *)(param_1 + 0xc) = fVar1;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0x24);
    *(float *)(param_1 + 0x24) = FLOAT_803e4650;
  }
  return;
}
