// Function: FUN_80143b78
// Entry: 80143b78
// Size: 140 bytes

undefined4 FUN_80143b78(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_8014460c();
  if (iVar1 == 0) {
    iVar1 = FUN_8013b368((double)FLOAT_803e2408,param_1,param_2);
    if (iVar1 == 1) {
      if (FLOAT_803e23dc == *(float *)(param_2 + 0x71c)) {
        *(undefined *)(param_2 + 10) = 0;
      }
      uVar2 = 1;
    }
    else {
      *(undefined *)(param_2 + 10) = 0;
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

