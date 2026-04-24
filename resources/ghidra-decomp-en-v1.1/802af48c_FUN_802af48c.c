// Function: FUN_802af48c
// Entry: 802af48c
// Size: 520 bytes

void FUN_802af48c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  ushort uVar2;
  int iVar3;
  
  if (*(char *)(param_10 + 0x8b3) == '\0') {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x47b,0,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x47f,0,param_12,param_13,param_14,param_15,param_16);
  }
  *(float *)(param_11 + 0x2a0) = FLOAT_803e8bb8;
  *(undefined2 *)(param_10 + 0x478) = *(undefined2 *)(param_10 + 0x484);
  *(float *)(param_10 + 0x844) = FLOAT_803e8b3c;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xef | 0x10;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0x7f;
  FUN_8017082c();
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfd;
  *(uint *)(param_10 + 0x360) = *(uint *)(param_10 + 0x360) | 0x800000;
  FUN_80035f9c((int)param_9);
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xf7;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
  *(undefined *)(param_10 + 0x40d) = 0;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xbf;
  *(undefined4 *)(param_10 + 0x488) = 0;
  *(undefined4 *)(param_10 + 0x47c) = 0;
  *(undefined4 *)(param_10 + 0x48c) = 0;
  *(undefined4 *)(param_10 + 0x480) = 0;
  DAT_803dd2d4 = 4;
  *(undefined *)(param_10 + 0x800) = 0;
  iVar3 = *(int *)(param_10 + 0x7f8);
  if (iVar3 != 0) {
    if ((*(short *)(iVar3 + 0x46) == 0x3cf) || (*(short *)(iVar3 + 0x46) == 0x662)) {
      FUN_80182a5c(iVar3);
    }
    else {
      FUN_800ea9f8(iVar3);
    }
    *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) =
         *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) & 0xbfff;
    *(undefined4 *)(*(int *)(param_10 + 0x7f8) + 0xf8) = 0;
    *(undefined4 *)(param_10 + 0x7f8) = 0;
  }
  if ((*(byte *)(param_10 + 0x3f1) >> 5 & 1) != 0) {
    sVar1 = *param_9;
    *(short *)(param_10 + 0x484) = sVar1;
    *(short *)(param_10 + 0x478) = sVar1;
    *(int *)(param_10 + 0x494) = (int)sVar1;
    *(float *)(param_10 + 0x284) = FLOAT_803e8b3c;
  }
  *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xdf;
  if (*(float *)(param_10 + 0x838) <= FLOAT_803e8b78) {
    if (*(short *)(param_10 + 0x81a) == 0) {
      uVar2 = 0x3ce;
    }
    else {
      uVar2 = 0x2e;
    }
    FUN_8000bb38((uint)param_9,uVar2);
  }
  else {
    FUN_8000bb38((uint)param_9,0x427);
  }
  return;
}

