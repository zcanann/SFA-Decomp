// Function: FUN_80124a78
// Entry: 80124a78
// Size: 192 bytes

undefined4 FUN_80124a78(int param_1,int *param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 local_18;
  
  local_18 = DAT_803e2a94;
  iVar1 = FUN_800284e8(*param_2,param_3);
  FUN_80052a6c();
  local_18 = CONCAT31(local_18._0_3_,*(undefined *)(param_1 + 0x37));
  uVar2 = FUN_8005383c(*(uint *)(iVar1 + 0x24));
  FUN_80052134(uVar2,0,0,(char *)&local_18,0,1);
  FUN_80052a38();
  FUN_8025cce8(1,4,5,5);
  FUN_8007048c(0,7,0);
  FUN_80070434(0);
  FUN_8025c754(7,0,0,7,0);
  return 1;
}

