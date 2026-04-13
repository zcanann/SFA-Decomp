// Function: FUN_80167e34
// Entry: 80167e34
// Size: 216 bytes

undefined4
FUN_80167e34(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      if (*(int *)(param_9 + 0x4c) == 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    *(undefined *)(*(int *)(iVar1 + 0x40c) + 0x4b) = 0;
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,7);
    FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    *(ushort *)(iVar1 + 0x400) = *(ushort *)(iVar1 + 0x400) | 0x20;
    *(float *)(iVar1 + 1000) = FLOAT_803e3d10;
    *(float *)(iVar1 + 0x3ec) = FLOAT_803e3d14;
  }
  return 0;
}

