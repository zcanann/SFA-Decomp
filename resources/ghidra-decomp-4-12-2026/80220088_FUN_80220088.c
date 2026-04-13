// Function: FUN_80220088
// Entry: 80220088
// Size: 124 bytes

void FUN_80220088(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  if ((*(ushort *)(param_9 + 0xb0) & 0x200) == 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    FUN_80035ff8(param_9);
    *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) & 0xfdff;
    FUN_8002cf80(param_9);
    *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x8000;
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
  }
  return;
}

