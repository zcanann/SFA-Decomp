// Function: FUN_802546e0
// Entry: 802546e0
// Size: 892 bytes

undefined4 FUN_802546e0(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  undefined4 uVar10;
  undefined *puVar11;
  code *pcVar12;
  int unaff_r29;
  undefined4 local_24;
  
  iVar1 = param_1 * 0x40;
  if ((param_1 < 2) && (param_2 == 0)) {
    iVar9 = FUN_80253960(param_1);
    if (iVar9 == 0) {
      return 0;
    }
    if ((&DAT_803ae420)[param_1 * 0x10] == (&DAT_800030c0)[param_1]) {
      *param_3 = *(undefined4 *)(&DAT_803ae41c + iVar1);
      return (&DAT_803ae420)[param_1 * 0x10];
    }
    uVar10 = FUN_8024377c();
    if (((*(uint *)(&DAT_803ae40c + iVar1) & 8) == 0) && (iVar9 = FUN_80253960(param_1), iVar9 != 0)
       ) {
      FUN_8025389c(param_1,1,0,0);
      *(undefined4 *)(&DAT_803ae408 + iVar1) = 0;
      FUN_80243bcc(0x100000 >> param_1 * 3);
      *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) | 8;
      FUN_802437a4(uVar10);
      bVar2 = true;
    }
    else {
      FUN_802437a4(uVar10);
      bVar2 = false;
    }
    if (!bVar2) {
      return 0;
    }
    unaff_r29 = (&DAT_800030c0)[param_1];
  }
  bVar2 = false;
  if ((param_1 < 2) && (param_2 == 0)) {
    bVar2 = true;
  }
  if (bVar2) {
    puVar11 = &LAB_802546b8;
  }
  else {
    puVar11 = (undefined *)0x0;
  }
  uVar10 = FUN_802544d0(param_1,param_2,puVar11);
  uVar3 = countLeadingZeros(uVar10);
  uVar3 = uVar3 >> 5;
  if (uVar3 == 0) {
    uVar10 = FUN_80253dd0(param_1,param_2,0);
    uVar4 = countLeadingZeros(uVar10);
    uVar3 = uVar4 >> 5;
    if (uVar3 == 0) {
      local_24 = 0;
      uVar10 = FUN_8025327c(param_1,&local_24,2,1,0);
      uVar3 = countLeadingZeros(uVar10);
      uVar10 = FUN_80253664(param_1);
      uVar5 = countLeadingZeros(uVar10);
      uVar10 = FUN_8025327c(param_1,param_3,4,0,0);
      uVar6 = countLeadingZeros(uVar10);
      uVar10 = FUN_80253664(param_1);
      uVar7 = countLeadingZeros(uVar10);
      uVar10 = FUN_80253efc(param_1);
      uVar8 = countLeadingZeros(uVar10);
      uVar3 = (uVar4 | uVar3 | uVar5 | uVar6 | uVar7 | uVar8) >> 5;
    }
    uVar10 = FUN_8024377c();
    if ((*(uint *)(&DAT_803ae40c + iVar1) & 0x10) == 0) {
      FUN_802437a4(uVar10);
    }
    else {
      *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) & 0xffffffef;
      FUN_80253188(param_1,&DAT_803ae400 + iVar1);
      if (0 < *(int *)(&DAT_803ae424 + iVar1)) {
        iVar9 = *(int *)(&DAT_803ae424 + iVar1) + -1;
        pcVar12 = *(code **)(&DAT_803ae42c + iVar1);
        *(int *)(&DAT_803ae424 + iVar1) = iVar9;
        if (0 < iVar9) {
          FUN_8028f2cc(&DAT_803ae428 + iVar1,&DAT_803ae430 + iVar1,
                       *(int *)(&DAT_803ae424 + iVar1) << 3);
        }
        (*pcVar12)(param_1,0);
      }
      FUN_802437a4(uVar10);
    }
  }
  if ((param_1 < 2) && (param_2 == 0)) {
    uVar10 = FUN_8024377c();
    if ((*(uint *)(&DAT_803ae40c + iVar1) & 8) == 0) {
      FUN_802437a4(uVar10);
    }
    else if (((*(uint *)(&DAT_803ae40c + iVar1) & 0x10) == 0) ||
            (*(int *)(&DAT_803ae418 + iVar1) != 0)) {
      *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) & 0xfffffff7;
      FUN_80243b44(0x500000 >> param_1 * 3);
      FUN_802437a4(uVar10);
    }
    else {
      FUN_802437a4(uVar10);
    }
    FUN_8024377c();
    uVar3 = uVar3 | (&DAT_800030c0)[param_1] != unaff_r29;
    if (uVar3 == 0) {
      *(undefined4 *)(&DAT_803ae41c + iVar1) = *param_3;
      (&DAT_803ae420)[param_1 * 0x10] = unaff_r29;
    }
    FUN_802437a4();
    if (uVar3 == 0) {
      uVar10 = (&DAT_803ae420)[param_1 * 0x10];
    }
    else {
      uVar10 = 0;
    }
  }
  else if (uVar3 == 0) {
    uVar10 = 1;
  }
  else {
    uVar10 = 0;
  }
  return uVar10;
}

