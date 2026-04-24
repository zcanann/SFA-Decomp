// Function: FUN_80244128
// Entry: 80244128
// Size: 220 bytes

undefined4 FUN_80244128(int param_1,undefined4 *param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_8024377c();
  while( true ) {
    if (*(int *)(param_1 + 0x1c) != 0) {
      if (param_2 != (undefined4 *)0x0) {
        *param_2 = *(undefined4 *)(*(int *)(param_1 + 0x10) + *(int *)(param_1 + 0x18) * 4);
      }
      iVar2 = *(int *)(param_1 + 0x18) + 1;
      *(int *)(param_1 + 0x18) =
           iVar2 - (iVar2 / *(int *)(param_1 + 0x14)) * *(int *)(param_1 + 0x14);
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + -1;
      FUN_80246b4c(param_1);
      FUN_802437a4(uVar1);
      return 1;
    }
    if ((param_3 & 1) == 0) break;
    FUN_80246a60(param_1 + 8);
  }
  FUN_802437a4(uVar1);
  return 0;
}

