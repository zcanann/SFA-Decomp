// Function: FUN_801d8204
// Entry: 801d8204
// Size: 128 bytes

undefined4
FUN_801d8204(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined4 param_10,int param_11)

{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_11 + iVar1 + 0x81) == '\0') {
      param_1 = FUN_801d86e4(*(uint **)(param_9 + 0xb8));
    }
  }
  FUN_801d8284(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               *(int *)(param_9 + 0xb8));
  return 0;
}

