// Function: FUN_801adb04
// Entry: 801adb04
// Size: 124 bytes

void FUN_801adb04(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (*(short *)(param_9 + 0x46) != 0x172) {
    if (*(char *)(*(int *)(param_9 + 0xb8) + 0xb) != '\0') {
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   (uint)*(ushort *)(*(int *)(param_9 + 0xb8) + 8),0,0,0,in_r9,in_r10);
    }
    (**(code **)(*DAT_803dd6f8 + 0x18))(param_9);
  }
  return;
}

