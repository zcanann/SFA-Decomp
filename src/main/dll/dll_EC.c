#include "ghidra_import.h"
#include "main/dll/dll_EC.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80017698();
extern uint FUN_80017a98();
extern undefined4 ObjHits_RecordObjectHit();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern int FUN_80294d6c();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e70d8;
extern f32 lbl_803DC074;
extern f32 lbl_803E70D0;

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateCooldownTrigger
 * EN v1.0 Address: 0x80206F30
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x80206FA0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateCooldownTrigger(void)
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
  uVar5 = FUN_80017a98();
  iVar6 = 0;
  cVar9 = '\0';
  cVar8 = '\0';
  cVar7 = '\0';
  fVar1 = *(float *)(uVar5 + 0xc) - *(float *)(iVar4 + 0xc);
  fVar2 = *(float *)(uVar5 + 0x10) - *(float *)(iVar4 + 0x10);
  fVar3 = *(float *)(uVar5 + 0x14) - *(float *)(iVar4 + 0x14);
  if (fVar1 <= lbl_803E70D0) {
    local_28 = (double)CONCAT44(0x43300000,(int)*psVar10 ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e70d8) < fVar1) {
      iVar6 = 1;
      cVar9 = '\x01';
    }
  }
  if (lbl_803E70D0 < fVar1) {
    local_28 = (double)CONCAT44(0x43300000,(int)*psVar10 ^ 0x80000000);
    if (fVar1 < (float)(local_28 - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar9 = cVar9 + -1;
    }
  }
  if (fVar3 <= lbl_803E70D0) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[1] ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e70d8) < fVar3) {
      iVar6 = iVar6 + 1;
      cVar7 = '\x01';
    }
  }
  if (lbl_803E70D0 < fVar3) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[1] ^ 0x80000000);
    if (fVar3 < (float)(local_28 - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar7 = cVar7 + -1;
    }
  }
  if (fVar2 <= lbl_803E70D0) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[2] ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e70d8) < fVar2) {
      iVar6 = iVar6 + 1;
      cVar8 = '\x01';
    }
  }
  if (lbl_803E70D0 < fVar2) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[2] ^ 0x80000000);
    if (fVar2 < (float)(local_28 - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar8 = cVar8 + -1;
    }
  }
  if (-1 < psVar10[3]) {
    psVar10[3] = psVar10[3] - (short)(int)lbl_803DC074;
  }
  if ((iVar6 == 3) && (psVar10[3] < 1)) {
    iVar4 = FUN_80294d6c(uVar5);
    if (iVar4 == 0x1d7) {
      FUN_80017698(0x468,1);
      (**(code **)(*DAT_803dd708 + 8))(uVar5,0x397,0,2,0xffffffff,0);
    }
    else {
      ObjHits_RecordObjectHit(uVar5,0,'\x14',2,0);
    }
    FUN_80006824(uVar5,0x1ca);
    psVar10[3] = 200;
  }
  *(char *)(psVar10 + 8) = cVar9;
  *(char *)((int)psVar10 + 0x11) = cVar8;
  *(char *)(psVar10 + 9) = cVar7;
  FUN_80286888();
  return;
}
