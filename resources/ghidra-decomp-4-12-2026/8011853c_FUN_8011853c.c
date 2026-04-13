// Function: FUN_8011853c
// Entry: 8011853c
// Size: 144 bytes

undefined4 FUN_8011853c(undefined4 param_1,int *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_2 == (int *)0x0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_800284e8(*param_2,param_3);
  }
  if (((iVar1 == 0) || (*(char *)(iVar1 + 0x29) == '\x01')) && (DAT_803de288 == 2)) {
    FUN_80117910(*DAT_803a6aac,DAT_803a6aac[1],DAT_803a6aac[2],(int)(short)DAT_803a6a40,
                 (int)(short)DAT_803a6a44);
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

