// Function: FUN_8002e4f4
// Entry: 8002e4f4
// Size: 128 bytes

void FUN_8002e4f4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  for (iVar1 = 0; iVar1 < DAT_803dd814; iVar1 = iVar1 + 1) {
    if (*(int *)(DAT_803dd818 + iVar2) != 0) {
      param_1 = FUN_8002bf60(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *(undefined4 *)(DAT_803dd818 + iVar2) = 0;
    }
    iVar2 = iVar2 + 4;
  }
  DAT_803dd814 = 0;
  return;
}

