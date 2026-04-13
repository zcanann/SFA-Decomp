// Function: FUN_80232d40
// Entry: 80232d40
// Size: 376 bytes

void FUN_80232d40(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11)

{
  int iVar1;
  undefined8 uVar2;
  
  if ((*(byte *)(param_10 + 0x160) >> 5 & 1) == 0) {
    iVar1 = FUN_80080434((float *)(param_10 + 0x124));
    if (iVar1 != 0) {
      *(byte *)(param_10 + 0x160) = *(byte *)(param_10 + 0x160) & 0xdf | 0x20;
      FUN_800803f8((undefined4 *)(param_10 + 0x128));
      FUN_80080404((float *)(param_10 + 0x128),(ushort)*(byte *)(param_11 + 0x2d));
      *(undefined *)(param_10 + 0x155) = *(undefined *)(param_11 + 0x2e);
      *(short *)(param_10 + 0x14e) = -*(short *)(param_11 + 0x2a);
    }
  }
  else {
    iVar1 = FUN_80080434((float *)(param_10 + 0x128));
    if (iVar1 != 0) {
      uVar2 = FUN_8023293c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0
                           ,(int)*(short *)(param_10 + 0x14e),
                           (int)*(char *)(param_10 + 0x155) == (uint)*(byte *)(param_11 + 0x2e));
      if (1 < *(byte *)(param_10 + 0x15b)) {
        FUN_8023293c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,
                     (int)*(short *)(param_10 + 0x14e),'\0');
      }
      *(char *)(param_10 + 0x155) = *(char *)(param_10 + 0x155) + -1;
      FUN_800803f8((undefined4 *)(param_10 + 0x128));
      FUN_80080404((float *)(param_10 + 0x128),(ushort)*(byte *)(param_11 + 0x2d));
      *(short *)(param_10 + 0x14e) =
           *(short *)(param_10 + 0x14e) +
           (short)(((uint)*(ushort *)(param_11 + 0x2a) << 1) / (uint)*(byte *)(param_11 + 0x2e));
      if (*(char *)(param_10 + 0x155) < '\x01') {
        *(byte *)(param_10 + 0x160) = *(byte *)(param_10 + 0x160) & 0xdf;
        FUN_800803f8((undefined4 *)(param_10 + 0x124));
        FUN_80080404((float *)(param_10 + 0x124),(ushort)*(byte *)(param_11 + 0x2c));
      }
    }
  }
  return;
}

