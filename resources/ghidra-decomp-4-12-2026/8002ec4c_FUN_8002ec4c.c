// Function: FUN_8002ec4c
// Entry: 8002ec4c
// Size: 452 bytes

void FUN_8002ec4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10,int param_11,uint param_12,undefined2 param_13)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = (int)*(short *)(param_10 + ((int)param_12 >> 8) * 2 + 0x70) + (param_12 & 0xff);
  if ((int)(uint)*(ushort *)(param_10 + 0xec) <= iVar3) {
    iVar3 = *(ushort *)(param_10 + 0xec) - 1;
  }
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if ((*(ushort *)(param_10 + 2) & 0x40) == 0) {
    *(short *)(param_11 + 0x48) = (short)iVar3;
    iVar3 = *(int *)(*(int *)(param_10 + 100) + (uint)*(ushort *)(param_11 + 0x48) * 4);
  }
  else {
    if (*(short *)(param_11 + 100) != iVar3) {
      *(short *)(param_11 + 0x48) = (short)*(char *)(param_11 + 0x62);
      *(short *)(param_11 + 0x4a) = 1 - *(char *)(param_11 + 0x62);
      if (*(short *)(*(int *)(param_10 + 0x6c) + iVar3 * 2) == -1) {
        param_1 = FUN_8007d858();
        iVar3 = 0;
      }
      FUN_80024f40(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)*(short *)(*(int *)(param_10 + 0x6c) + iVar3 * 2),(int)(short)iVar3,
                   *(undefined4 *)(param_11 + (uint)*(ushort *)(param_11 + 0x48) * 4 + 0x24),
                   param_10);
      *(short *)(param_11 + 100) = (short)iVar3;
    }
    iVar3 = *(int *)(param_11 + (uint)*(ushort *)(param_11 + 0x48) * 4 + 0x24) + 0x80;
  }
  *(int *)(param_11 + 0x3c) = iVar3 + 6;
  uVar2 = (int)*(char *)(iVar3 + 1) & 0xf0;
  if (uVar2 == (int)*(char *)(param_11 + 0x60)) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_11 + 0x3c) + 1)) -
                   DOUBLE_803df568);
    if (uVar2 == 0) {
      fVar1 = fVar1 - FLOAT_803df560;
    }
    if (fVar1 == *(float *)(param_11 + 0x14)) {
      *(undefined2 *)(param_11 + 0x5a) = param_13;
    }
    else {
      *(undefined2 *)(param_11 + 0x5a) = 0;
    }
  }
  else {
    *(undefined2 *)(param_11 + 0x5a) = 0;
  }
  return;
}

