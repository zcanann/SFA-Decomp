// Function: FUN_80119688
// Entry: 80119688
// Size: 156 bytes

bool FUN_80119688(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = FUN_802462a8(&DAT_803a6f08,FUN_80119520,0,&DAT_803a6f08,0x1000,param_1,1);
  if (iVar1 != 0) {
    FUN_80244000(&DAT_803a72d0,&DAT_803a7268,10);
    FUN_80244000(&DAT_803a72b0,&DAT_803a7240,10);
    FUN_80244000(&DAT_803a7290,&DAT_803a7218,10);
    DAT_803dd688 = 1;
  }
  return iVar1 != 0;
}

