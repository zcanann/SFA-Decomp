// Function: FUN_8002e38c
// Entry: 8002e38c
// Size: 360 bytes

void FUN_8002e38c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dd814; iVar2 = iVar2 + 1) {
    if (*(int *)(DAT_803dd818 + iVar1) != 0) {
      param_1 = FUN_8002bf60(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *(undefined4 *)(DAT_803dd818 + iVar1) = 0;
    }
    iVar1 = iVar1 + 4;
  }
  DAT_803dd814 = 0;
  DAT_803dc0a8 = 0;
  iVar2 = DAT_803dd804 + -1;
  iVar1 = iVar2 * 4;
  for (; -1 < iVar2; iVar2 = iVar2 + -1) {
    param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(DAT_803dd808 + iVar1));
    iVar1 = iVar1 + -4;
  }
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dd814; iVar2 = iVar2 + 1) {
    if (*(int *)(DAT_803dd818 + iVar1) != 0) {
      param_1 = FUN_8002bf60(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *(undefined4 *)(DAT_803dd818 + iVar1) = 0;
    }
    iVar1 = iVar1 + 4;
  }
  DAT_803dc0a8 = 2;
  DAT_803dd814 = 0;
  DAT_803dd80c = 0;
  DAT_803dd804 = 0;
  FUN_80013b8c(-0x7fc22804,0x38);
  DAT_803dd814 = 0;
  DAT_803dd80c = 0;
  DAT_803dd7f0 = 0;
  DAT_803dd804 = 0;
  FUN_80013b8c(-0x7fc22804,0x38);
  DAT_803dd844 = 0;
  FUN_80037544();
  FUN_80036ae8();
  (**(code **)(*DAT_803dd6d0 + 0x28))(0,0);
  FUN_8000ce74();
  return;
}

