// Function: FUN_80212ab0
// Entry: 80212ab0
// Size: 360 bytes

undefined4 FUN_80212ab0(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_18;
  undefined4 local_14 [2];
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
    *(undefined *)(DAT_803ddd54 + 0x3f) = 1;
    *(float *)(param_2 + 0x294) =
         *(float *)(iVar2 + (uint)*(byte *)(DAT_803ddd54 + 0x3f) * 4 + 0x38) / FLOAT_803e67c4;
  }
  iVar2 = FUN_8002208c((double)FLOAT_803e67c8,(double)FLOAT_803e67cc,DAT_803ddd54 + 100);
  if (iVar2 != 0) {
    FUN_8000bb18(param_1,0x8f);
  }
  iVar2 = FUN_80214b9c(param_2);
  if (iVar2 == 0) {
    iVar2 = FUN_80214d3c(param_1);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = 8;
    }
  }
  else {
    *(char *)((int)DAT_803ddd54 + 0x103) = *(char *)((int)DAT_803ddd54 + 0x103) + -1;
    if (*(char *)((int)DAT_803ddd54 + 0x103) < '\x01') {
      local_14[0] = 2;
      iVar2 = FUN_800138c4(*DAT_803ddd54);
      if (iVar2 == 0) {
        FUN_80013958(*DAT_803ddd54,local_14);
      }
    }
    else {
      local_18 = 5;
      iVar2 = FUN_800138c4(*DAT_803ddd54);
      if (iVar2 == 0) {
        FUN_80013958(*DAT_803ddd54,&local_18);
      }
    }
    uVar1 = 4;
  }
  return uVar1;
}

