// Function: FUN_80119b58
// Entry: 80119b58
// Size: 200 bytes

undefined4 FUN_80119b58(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_802462a8(&DAT_803a8348,FUN_80119a1c,0,&DAT_803a8348,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_802462a8(&DAT_803a8348,FUN_801198e0,param_2,&DAT_803a8348,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_80244000(&DAT_803a7328,&DAT_803a72fc,3);
  FUN_80244000(&DAT_803a7308,&DAT_803a72f0,3);
  DAT_803dd690 = 1;
  DAT_803dd694 = 1;
  return 1;
}

