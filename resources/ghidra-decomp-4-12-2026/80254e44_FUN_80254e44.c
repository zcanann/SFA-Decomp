// Function: FUN_80254e44
// Entry: 80254e44
// Size: 892 bytes

undefined4 FUN_80254e44(int param_1,int param_2,byte *param_3)

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
  byte local_24 [4];
  
  iVar1 = param_1 * 0x40;
  if ((param_1 < 2) && (param_2 == 0)) {
    iVar9 = FUN_802540c4(param_1);
    if (iVar9 == 0) {
      return 0;
    }
    if ((&DAT_803af080)[param_1 * 0x10] == (&DAT_800030c0)[param_1]) {
      *(undefined4 *)param_3 = *(undefined4 *)(&DAT_803af07c + iVar1);
      return (&DAT_803af080)[param_1 * 0x10];
    }
    FUN_80243e74();
    if (((*(uint *)(&DAT_803af06c + iVar1) & 8) == 0) && (iVar9 = FUN_802540c4(param_1), iVar9 != 0)
       ) {
      FUN_80254000(param_1,1,0,0);
      *(undefined4 *)(&DAT_803af068 + iVar1) = 0;
      FUN_802442c4(0x100000 >> param_1 * 3);
      *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) | 8;
      FUN_80243e9c();
      bVar2 = true;
    }
    else {
      FUN_80243e9c();
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
    puVar11 = &LAB_80254e1c;
  }
  else {
    puVar11 = (undefined *)0x0;
  }
  uVar10 = FUN_80254c34(param_1,param_2,(int)puVar11);
  uVar3 = countLeadingZeros(uVar10);
  uVar3 = uVar3 >> 5;
  if (uVar3 == 0) {
    uVar10 = FUN_80254534(param_1,param_2,0);
    uVar4 = countLeadingZeros(uVar10);
    uVar3 = uVar4 >> 5;
    if (uVar3 == 0) {
      local_24[0] = 0;
      local_24[1] = 0;
      local_24[2] = 0;
      local_24[3] = 0;
      uVar10 = FUN_802539e0(param_1,local_24,2,1,0);
      uVar3 = countLeadingZeros(uVar10);
      uVar10 = FUN_80253dc8(param_1);
      uVar5 = countLeadingZeros(uVar10);
      uVar10 = FUN_802539e0(param_1,param_3,4,0,0);
      uVar6 = countLeadingZeros(uVar10);
      uVar10 = FUN_80253dc8(param_1);
      uVar7 = countLeadingZeros(uVar10);
      uVar10 = FUN_80254660(param_1);
      uVar8 = countLeadingZeros(uVar10);
      uVar3 = (uVar4 | uVar3 | uVar5 | uVar6 | uVar7 | uVar8) >> 5;
    }
    FUN_80243e74();
    if ((*(uint *)(&DAT_803af06c + iVar1) & 0x10) == 0) {
      FUN_80243e9c();
    }
    else {
      *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) & 0xffffffef;
      FUN_802538ec(param_1,(int *)(&DAT_803af060 + iVar1));
      if (0 < *(int *)(&DAT_803af084 + iVar1)) {
        iVar9 = *(int *)(&DAT_803af084 + iVar1) + -1;
        pcVar12 = *(code **)(&DAT_803af08c + iVar1);
        *(int *)(&DAT_803af084 + iVar1) = iVar9;
        if (0 < iVar9) {
          FUN_8028fa2c((uint)(&DAT_803af088 + iVar1),(uint)(&DAT_803af090 + iVar1),
                       *(int *)(&DAT_803af084 + iVar1) << 3);
        }
        (*pcVar12)(param_1,0);
      }
      FUN_80243e9c();
    }
  }
  if ((param_1 < 2) && (param_2 == 0)) {
    FUN_80243e74();
    if ((*(uint *)(&DAT_803af06c + iVar1) & 8) == 0) {
      FUN_80243e9c();
    }
    else if (((*(uint *)(&DAT_803af06c + iVar1) & 0x10) == 0) ||
            (*(int *)(&DAT_803af078 + iVar1) != 0)) {
      *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) & 0xfffffff7;
      FUN_8024423c(0x500000 >> param_1 * 3);
      FUN_80243e9c();
    }
    else {
      FUN_80243e9c();
    }
    FUN_80243e74();
    iVar9 = (&DAT_800030c0)[param_1];
    if (uVar3 == 0 && iVar9 == unaff_r29) {
      *(undefined4 *)(&DAT_803af07c + iVar1) = *(undefined4 *)param_3;
      (&DAT_803af080)[param_1 * 0x10] = unaff_r29;
    }
    FUN_80243e9c();
    if (uVar3 == 0 && iVar9 == unaff_r29) {
      uVar10 = (&DAT_803af080)[param_1 * 0x10];
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

