#include "ghidra_import.h"
#include "main/dll/dll_EC.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_800201ac();
extern uint FUN_8002bac4();
extern undefined4 FUN_80036548();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern int FUN_80297300();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e70d8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e70d0;

/*
 * --INFO--
 *
 * Function: FUN_80206fa0
 * EN v1.0 Address: 0x80206F30
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x80206FA0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80206fa0(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  char cVar7;
  char cVar8;
  char cVar9;
  short *psVar10;
  undefined8 local_28;
  
  iVar4 = FUN_8028683c();
  psVar10 = *(short **)(iVar4 + 0xb8);
  uVar5 = FUN_8002bac4();
  iVar6 = 0;
  cVar9 = '\0';
  cVar8 = '\0';
  cVar7 = '\0';
  fVar1 = *(float *)(uVar5 + 0xc) - *(float *)(iVar4 + 0xc);
  fVar2 = *(float *)(uVar5 + 0x10) - *(float *)(iVar4 + 0x10);
  fVar3 = *(float *)(uVar5 + 0x14) - *(float *)(iVar4 + 0x14);
  if (fVar1 <= FLOAT_803e70d0) {
    local_28 = (double)CONCAT44(0x43300000,(int)*psVar10 ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e70d8) < fVar1) {
      iVar6 = 1;
      cVar9 = '\x01';
    }
  }
  if (FLOAT_803e70d0 < fVar1) {
    local_28 = (double)CONCAT44(0x43300000,(int)*psVar10 ^ 0x80000000);
    if (fVar1 < (float)(local_28 - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar9 = cVar9 + -1;
    }
  }
  if (fVar3 <= FLOAT_803e70d0) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[1] ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e70d8) < fVar3) {
      iVar6 = iVar6 + 1;
      cVar7 = '\x01';
    }
  }
  if (FLOAT_803e70d0 < fVar3) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[1] ^ 0x80000000);
    if (fVar3 < (float)(local_28 - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar7 = cVar7 + -1;
    }
  }
  if (fVar2 <= FLOAT_803e70d0) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[2] ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e70d8) < fVar2) {
      iVar6 = iVar6 + 1;
      cVar8 = '\x01';
    }
  }
  if (FLOAT_803e70d0 < fVar2) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[2] ^ 0x80000000);
    if (fVar2 < (float)(local_28 - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar8 = cVar8 + -1;
    }
  }
  if (-1 < psVar10[3]) {
    psVar10[3] = psVar10[3] - (short)(int)FLOAT_803dc074;
  }
  if ((iVar6 == 3) && (psVar10[3] < 1)) {
    iVar4 = FUN_80297300(uVar5);
    if (iVar4 == 0x1d7) {
      FUN_800201ac(0x468,1);
      (**(code **)(*DAT_803dd708 + 8))(uVar5,0x397,0,2,0xffffffff,0);
    }
    else {
      FUN_80036548(uVar5,0,'\x14',2,0);
    }
    FUN_8000bb38(uVar5,0x1ca);
    psVar10[3] = 200;
  }
  *(char *)(psVar10 + 8) = cVar9;
  *(char *)((int)psVar10 + 0x11) = cVar8;
  *(char *)(psVar10 + 9) = cVar7;
  FUN_80286888();
  return;
}
