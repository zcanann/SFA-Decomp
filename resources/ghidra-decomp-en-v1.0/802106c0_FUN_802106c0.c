// Function: FUN_802106c0
// Entry: 802106c0
// Size: 268 bytes

void FUN_802106c0(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e6740;
  uVar1 = FUN_8002b9ec();
  iVar2 = FUN_8001ffb4(0x499);
  if (iVar2 == 0) {
    iVar2 = FUN_8001ffb4(0x2e8);
    if (iVar2 != 0) {
      *(undefined *)(param_2 + 8) = 4;
      FUN_800550c4((double)FLOAT_803e6744,0);
      FUN_800200e8(0x497,0);
      FUN_800200e8(0x49d,0);
    }
  }
  else {
    FUN_800200e8(0x499,1);
    FUN_800550c4((double)FLOAT_803e6744,0);
    iVar2 = FUN_8001ffb4(0x4a9);
    if ((iVar2 != 0) && (iVar2 = FUN_802972a8(uVar1), iVar2 == 0)) {
      iVar2 = FUN_80036e58(0x1e,param_1,local_18);
      if (iVar2 != 0) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,1);
      }
      *(undefined *)(param_2 + 8) = 5;
    }
  }
  return;
}

