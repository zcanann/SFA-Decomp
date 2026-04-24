// Function: FUN_80003140
// Entry: 80003140
// Size: 312 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80003140(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  uint in_r7;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int *piVar5;
  int iVar6;
  undefined8 uVar7;
  
  FUN_80003278();
  FUN_80003354();
  uVar7 = FUN_80003294();
  DAT_80000044 = 0;
  if (DAT_800000f4 == 0) {
    uVar2 = _DAT_800030e8;
    if (DAT_80000034 != 0) goto LAB_800031a8;
  }
  else {
    uVar2 = *(uint *)(DAT_800000f4 + 0xc);
LAB_800031a8:
    in_r7 = uVar2;
    iVar1 = 0;
    if (in_r7 != 2) {
      if (in_r7 != 3) goto LAB_800031d0;
      iVar1 = 1;
    }
    FUN_8028d0f0((int)((ulonglong)uVar7 >> 0x20),(int)uVar7,iVar1,FUN_8028d0f0,in_r7,in_r8,in_r9,
                 in_r10);
  }
LAB_800031d0:
  iVar1 = DAT_800000f4;
  piVar3 = &DAT_800000f4;
  if ((DAT_800000f4 != 0) && (piVar3 = *(int **)(DAT_800000f4 + 8), piVar3 != (int *)0x0)) {
    piVar3 = (int *)(DAT_800000f4 + (int)piVar3);
    iVar4 = *piVar3;
    if (iVar4 != 0) {
      piVar5 = piVar3 + 1;
      iVar6 = iVar4;
      do {
        piVar3 = piVar3 + 1;
        *piVar3 = *piVar3 + iVar1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      in_r7 = (uint)piVar5 & 0xffffffe0;
      DAT_80000034 = in_r7;
      goto LAB_80003238;
    }
  }
  iVar4 = 0;
  piVar5 = (int *)0x0;
LAB_80003238:
  FUN_802474cc();
  FUN_80240c5c();
  uVar2 = DAT_800030e6 & 0x8000;
  if (((DAT_800030e6 & 0x8000) == 0) || ((DAT_800030e6 & 0x7fff) == 1)) {
    FUN_80003100();
  }
  uVar7 = FUN_80247438();
  FUN_80021400(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,piVar5,uVar2,
               (int)piVar3,in_r7,in_r8,in_r9,in_r10);
  FUN_8028dc08();
  return;
}

