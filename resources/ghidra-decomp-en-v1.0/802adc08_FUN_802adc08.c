// Function: FUN_802adc08
// Entry: 802adc08
// Size: 632 bytes

undefined4 FUN_802adc08(int param_1,int param_2,int param_3)

{
  float fVar1;
  short sVar2;
  float fVar3;
  undefined4 uVar4;
  byte bVar5;
  undefined2 uVar6;
  
  *(float *)(param_1 + 0x28) = -(FLOAT_803dc67c * FLOAT_803db414 - *(float *)(param_1 + 0x28));
  if ((5 < *(byte *)(param_2 + 0x40c)) && ((*(byte *)(param_2 + 0x3f1) & 1) != 0)) {
    FUN_80014aa0((double)FLOAT_803e7f10);
    uVar6 = FUN_8006ed24(*(undefined *)(param_2 + 0x86c),*(undefined *)(param_2 + 0x8a5));
    FUN_8000bb18(param_1,uVar6);
    if (*(short *)(param_2 + 0x81a) == 0) {
      uVar4 = 0x2cf;
    }
    else {
      uVar4 = 0x25;
    }
    FUN_8000bb18(param_1,uVar4);
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xf7;
    *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xf7 | 8;
    *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xef | 0x10;
  }
  if ((*(float *)(param_1 + 0x1c) <= *(float *)(param_2 + 0x850)) ||
     ((((*(byte *)(param_3 + 0x264) & 2) != 0 && ((*(byte *)(param_3 + 0x264) & 0x20) == 0)) ||
      (*(char *)(param_3 + 0x262) != '\0')))) {
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef;
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xf7;
    FUN_80170380(DAT_803de450,2);
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfd;
    *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) | 0x800000;
    FUN_80035ea4(param_1);
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb | 4;
    *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xef;
    *(undefined *)(param_2 + 0x800) = 0;
    if (*(int *)(param_2 + 0x7f8) != 0) {
      sVar2 = *(short *)(*(int *)(param_2 + 0x7f8) + 0x46);
      if ((sVar2 == 0x3cf) || (sVar2 == 0x662)) {
        FUN_80182504();
      }
      else {
        FUN_800ea774();
      }
      *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) =
           *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(param_2 + 0x7f8) = 0;
    }
  }
  *(char *)(param_2 + 0x40c) = *(char *)(param_2 + 0x40c) + '\x01';
  bVar5 = *(byte *)(param_2 + 0x40c);
  if (10 < bVar5) {
    bVar5 = 10;
  }
  *(byte *)(param_2 + 0x40c) = bVar5;
  *(undefined *)(param_2 + 0x8c5) = 1;
  fVar3 = FLOAT_803e80c4;
  *(float *)(param_2 + 0x428) = FLOAT_803e80c4;
  fVar1 = FLOAT_803e7ff4;
  *(float *)(param_2 + 0x42c) = FLOAT_803e7ff4;
  *(float *)(param_2 + 0x430) = fVar3;
  *(float *)(param_2 + 0x434) = fVar1;
  *(float *)(param_2 + 0x82c) = FLOAT_803dc684;
  fVar1 = *(float *)(param_2 + 0x408);
  fVar3 = FLOAT_803e7ea4;
  if ((FLOAT_803e7ea4 <= fVar1) && (fVar3 = fVar1, *(float *)(param_2 + 0x404) < fVar1)) {
    fVar3 = *(float *)(param_2 + 0x404);
  }
  *(float *)(param_2 + 0x408) = fVar3;
  return 0;
}

