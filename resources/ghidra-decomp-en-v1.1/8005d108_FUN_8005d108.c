// Function: FUN_8005d108
// Entry: 8005d108
// Size: 304 bytes

void FUN_8005d108(int param_1,int param_2,int param_3)

{
  undefined2 *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  FUN_80259000(0x90,0,param_3 * 3 & 0xffff);
  for (iVar4 = 0; iVar4 < param_3; iVar4 = iVar4 + 1) {
    iVar5 = 0;
    iVar6 = 3;
    do {
      DAT_cc008000._0_1_ = 0;
      iVar2 = iVar5 + 1;
      puVar1 = (undefined2 *)(param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10);
      DAT_cc008000._0_2_ = *puVar1;
      DAT_cc008000._0_2_ = puVar1[1];
      DAT_cc008000._0_2_ = puVar1[2];
      iVar3 = param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10;
      DAT_cc008000._0_1_ = *(undefined *)(iVar3 + 0xc);
      DAT_cc008000._0_1_ = *(undefined *)(iVar3 + 0xd);
      DAT_cc008000._0_1_ = *(undefined *)(iVar3 + 0xe);
      DAT_cc008000._0_1_ = *(undefined *)(iVar3 + 0xf);
      iVar2 = param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10;
      DAT_cc008000._0_2_ = *(undefined2 *)(iVar2 + 8);
      DAT_cc008000._0_2_ = *(undefined2 *)(iVar2 + 10);
      iVar5 = iVar5 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    param_2 = param_2 + 0x10;
  }
  return;
}

