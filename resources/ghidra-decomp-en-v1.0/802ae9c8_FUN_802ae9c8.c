// Function: FUN_802ae9c8
// Entry: 802ae9c8
// Size: 868 bytes

void FUN_802ae9c8(short *param_1,int param_2,int param_3)

{
  float fVar1;
  short sVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  
  if (*(float *)(param_1 + 0x4c) <= FLOAT_803e7e98) {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x12,0);
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x91,0);
  }
  FUN_8002f574(param_1,0xf);
  *(float *)(param_2 + 0x404) = FLOAT_803e8068;
  *(float *)(param_2 + 0x408) =
       FLOAT_803e7ea0 * FLOAT_803e806c * *(float *)(param_3 + 0x298) +
       FLOAT_803e7eb4 * *(float *)(param_3 + 0x294);
  fVar1 = *(float *)(param_2 + 0x408);
  fVar3 = FLOAT_803e7f18;
  if ((FLOAT_803e7f18 <= fVar1) && (fVar3 = fVar1, *(float *)(param_2 + 0x404) < fVar1)) {
    fVar3 = *(float *)(param_2 + 0x404);
  }
  *(float *)(param_2 + 0x408) = fVar3;
  uVar4 = *(undefined4 *)(param_2 + 0x408);
  *(undefined4 *)(param_3 + 0x280) = uVar4;
  *(undefined4 *)(param_3 + 0x294) = uVar4;
  *(float *)(param_1 + 0x14) = *(float *)(param_3 + 0x280) / FLOAT_803e8068;
  fVar1 = *(float *)(param_1 + 0x14);
  fVar3 = FLOAT_803e7ea4;
  if ((FLOAT_803e7ea4 <= fVar1) && (fVar3 = fVar1, FLOAT_803e7ee0 < fVar1)) {
    fVar3 = FLOAT_803e7ee0;
  }
  *(float *)(param_1 + 0x14) = fVar3;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * FLOAT_803dc680;
  fVar1 = *(float *)(param_1 + 0x14);
  fVar3 = FLOAT_803e7e98;
  if ((FLOAT_803e7e98 <= fVar1) && (fVar3 = fVar1, FLOAT_803dc680 < fVar1)) {
    fVar3 = FLOAT_803dc680;
  }
  *(float *)(param_1 + 0x14) = fVar3;
  *(float *)(param_3 + 0x2a0) =
       FLOAT_803e7ee0 / ((FLOAT_803e7ed4 * FLOAT_803dc680) / FLOAT_803dc67c);
  *(undefined4 *)(param_2 + 0x84c) = *(undefined4 *)(param_1 + 0xe);
  *(float *)(param_2 + 0x850) = *(float *)(param_1 + 0xe) - FLOAT_803e7ed8;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xf7 | 8;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
  *(undefined *)(param_2 + 0x40d) = 0;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
  FUN_80170380(DAT_803de450,2);
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfd;
  *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) | 0x800000;
  FUN_80035ea4(param_1);
  if ((*(byte *)(param_2 + 0x3f0) >> 6 & 1) != 0) {
    *(short *)(param_2 + 0x484) = *(short *)(param_2 + 0x484) + -0x8000;
  }
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
  *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xfe;
  *(undefined *)(param_2 + 0x40c) = 0;
  if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
    sVar2 = *param_1;
    *(short *)(param_2 + 0x484) = sVar2;
    *(short *)(param_2 + 0x478) = sVar2;
    *(int *)(param_2 + 0x494) = (int)sVar2;
    *(float *)(param_2 + 0x284) = FLOAT_803e7ea4;
  }
  *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xdf;
  if (((((*(byte *)(param_2 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(param_2 + 0x8c8) != 'H')) &&
      (*(char *)(param_2 + 0x8c8) != 'G')) && (iVar5 = FUN_80080204(), iVar5 == 0)) {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
    *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xef;
  }
  if (*(short *)(param_2 + 0x81a) == 0) {
    uVar4 = 0x2d7;
  }
  else {
    uVar4 = 0x2d6;
  }
  FUN_8000bb18(param_1,uVar4);
  *(undefined *)(param_2 + 0x800) = 0;
  if (*(int *)(param_2 + 0x7f8) != 0) {
    sVar2 = *(short *)(*(int *)(param_2 + 0x7f8) + 0x46);
    if ((sVar2 == 0x3cf) || (sVar2 == 0x662)) {
      FUN_80182504();
    }
    else {
      FUN_800ea774();
    }
    *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) = *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff
    ;
    *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
    *(undefined4 *)(param_2 + 0x7f8) = 0;
  }
  return;
}

