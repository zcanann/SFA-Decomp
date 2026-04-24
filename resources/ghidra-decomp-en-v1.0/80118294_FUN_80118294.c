// Function: FUN_80118294
// Entry: 80118294
// Size: 144 bytes

undefined4 FUN_80118294(undefined4 param_1,undefined4 *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_2 == (undefined4 *)0x0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_80028424(*param_2,param_3);
  }
  if (((iVar1 == 0) || (*(char *)(iVar1 + 0x29) == '\x01')) && (DAT_803dd610 == 2)) {
    FUN_80117668(*DAT_803a5e4c,DAT_803a5e4c[1],DAT_803a5e4c[2],(int)(short)DAT_803a5de0,
                 (int)(short)DAT_803a5de4);
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

