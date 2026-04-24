// Function: FUN_8011784c
// Entry: 8011784c
// Size: 196 bytes

undefined4 FUN_8011784c(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_80246a0c(-0x7fc59f00,FUN_801177b4,0,0x803a6100,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_80246a0c(-0x7fc59f00,FUN_80117708,param_2,0x803a6100,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_802446f8((undefined4 *)&DAT_803a50e0,&DAT_803a50b4,3);
  FUN_802446f8((undefined4 *)&DAT_803a50c0,&DAT_803a50a8,3);
  DAT_803de2d8 = 1;
  return 1;
}

