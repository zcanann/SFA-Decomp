// Function: FUN_801a0db0
// Entry: 801a0db0
// Size: 128 bytes

void FUN_801a0db0(int param_1)

{
  short sVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0xf4) != 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (((sVar1 == 0x128) || (0x127 < sVar1)) || (sVar1 < 0x127)) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
    (**(code **)(*DAT_803dd6d4 + 0x48))(uVar2,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  return;
}

