// Function: FUN_80161638
// Entry: 80161638
// Size: 184 bytes

undefined4
FUN_80161638(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)

{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,8);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    param_1 = FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if (*(char *)(param_9 + 0x36) == '\0') {
    if (*(int *)(param_9 + 0x4c) == 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      uVar1 = 0;
    }
    else {
      uVar1 = 6;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

