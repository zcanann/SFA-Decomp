// Function: FUN_80210d38
// Entry: 80210d38
// Size: 268 bytes

void FUN_80210d38(undefined4 param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e73d8;
  iVar1 = FUN_8002bac4();
  uVar2 = FUN_80020078(0x499);
  if (uVar2 == 0) {
    uVar2 = FUN_80020078(0x2e8);
    if (uVar2 != 0) {
      *(undefined *)(param_2 + 8) = 4;
      FUN_80055240((double)FLOAT_803e73dc,0);
      FUN_800201ac(0x497,0);
      FUN_800201ac(0x49d,0);
    }
  }
  else {
    FUN_800201ac(0x499,1);
    FUN_80055240((double)FLOAT_803e73dc,0);
    uVar2 = FUN_80020078(0x4a9);
    if ((uVar2 != 0) && (iVar1 = FUN_80297a08(iVar1), iVar1 == 0)) {
      iVar1 = FUN_80036f50(0x1e,param_1,local_18);
      if (iVar1 != 0) {
        (**(code **)(**(int **)(iVar1 + 0x68) + 0x20))(iVar1,1);
      }
      *(undefined *)(param_2 + 8) = 5;
    }
  }
  return;
}

