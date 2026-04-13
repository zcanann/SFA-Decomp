// Function: FUN_802af128
// Entry: 802af128
// Size: 868 bytes

void FUN_802af128(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  undefined4 uVar2;
  short sVar3;
  float fVar4;
  ushort uVar5;
  int iVar6;
  
  if (*(float *)(param_9 + 0x4c) <= FLOAT_803e8b30) {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x12,0,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x91,0,param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8002f66c((int)param_9,0xf);
  *(float *)(param_10 + 0x404) = FLOAT_803e8d00;
  *(float *)(param_10 + 0x408) =
       FLOAT_803e8b38 * FLOAT_803e8d04 * *(float *)(param_11 + 0x298) +
       FLOAT_803e8b4c * *(float *)(param_11 + 0x294);
  fVar1 = *(float *)(param_10 + 0x408);
  fVar4 = FLOAT_803e8bb0;
  if ((FLOAT_803e8bb0 <= fVar1) && (fVar4 = fVar1, *(float *)(param_10 + 0x404) < fVar1)) {
    fVar4 = *(float *)(param_10 + 0x404);
  }
  *(float *)(param_10 + 0x408) = fVar4;
  uVar2 = *(undefined4 *)(param_10 + 0x408);
  *(undefined4 *)(param_11 + 0x280) = uVar2;
  *(undefined4 *)(param_11 + 0x294) = uVar2;
  *(float *)(param_9 + 0x14) = *(float *)(param_11 + 0x280) / FLOAT_803e8d00;
  fVar1 = *(float *)(param_9 + 0x14);
  fVar4 = FLOAT_803e8b3c;
  if ((FLOAT_803e8b3c <= fVar1) && (fVar4 = fVar1, FLOAT_803e8b78 < fVar1)) {
    fVar4 = FLOAT_803e8b78;
  }
  *(float *)(param_9 + 0x14) = fVar4;
  *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803dd2e8;
  fVar1 = *(float *)(param_9 + 0x14);
  fVar4 = FLOAT_803e8b30;
  if ((FLOAT_803e8b30 <= fVar1) && (fVar4 = fVar1, FLOAT_803dd2e8 < fVar1)) {
    fVar4 = FLOAT_803dd2e8;
  }
  *(float *)(param_9 + 0x14) = fVar4;
  *(float *)(param_11 + 0x2a0) =
       FLOAT_803e8b78 / ((FLOAT_803e8b6c * FLOAT_803dd2e8) / FLOAT_803dd2e4);
  *(undefined4 *)(param_10 + 0x84c) = *(undefined4 *)(param_9 + 0xe);
  *(float *)(param_10 + 0x850) = *(float *)(param_9 + 0xe) - FLOAT_803e8b70;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xf7 | 8;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
  *(undefined *)(param_10 + 0x40d) = 0;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xef;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0x7f;
  FUN_8017082c();
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfd;
  *(uint *)(param_10 + 0x360) = *(uint *)(param_10 + 0x360) | 0x800000;
  FUN_80035f9c((int)param_9);
  if ((*(byte *)(param_10 + 0x3f0) >> 6 & 1) != 0) {
    *(short *)(param_10 + 0x484) = *(short *)(param_10 + 0x484) + -0x8000;
  }
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xbf;
  *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xfe;
  *(undefined *)(param_10 + 0x40c) = 0;
  if ((*(byte *)(param_10 + 0x3f1) >> 5 & 1) != 0) {
    sVar3 = *param_9;
    *(short *)(param_10 + 0x484) = sVar3;
    *(short *)(param_10 + 0x478) = sVar3;
    *(int *)(param_10 + 0x494) = (int)sVar3;
    *(float *)(param_10 + 0x284) = FLOAT_803e8b3c;
  }
  *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xdf;
  if (((((*(byte *)(param_10 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(param_10 + 0x8c8) != 'H')) &&
      (*(char *)(param_10 + 0x8c8) != 'G')) && (iVar6 = FUN_80080490(), iVar6 == 0)) {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
    *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xef;
  }
  if (*(short *)(param_10 + 0x81a) == 0) {
    uVar5 = 0x2d7;
  }
  else {
    uVar5 = 0x2d6;
  }
  FUN_8000bb38((uint)param_9,uVar5);
  *(undefined *)(param_10 + 0x800) = 0;
  iVar6 = *(int *)(param_10 + 0x7f8);
  if (iVar6 != 0) {
    if ((*(short *)(iVar6 + 0x46) == 0x3cf) || (*(short *)(iVar6 + 0x46) == 0x662)) {
      FUN_80182a5c(iVar6);
    }
    else {
      FUN_800ea9f8(iVar6);
    }
    *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) =
         *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) & 0xbfff;
    *(undefined4 *)(*(int *)(param_10 + 0x7f8) + 0xf8) = 0;
    *(undefined4 *)(param_10 + 0x7f8) = 0;
  }
  return;
}

