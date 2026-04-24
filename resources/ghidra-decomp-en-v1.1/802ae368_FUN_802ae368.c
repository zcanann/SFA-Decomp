// Function: FUN_802ae368
// Entry: 802ae368
// Size: 632 bytes

undefined4 FUN_802ae368(uint param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  byte bVar3;
  ushort uVar5;
  int iVar4;
  
  *(float *)(param_1 + 0x28) = -(FLOAT_803dd2e4 * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
  if ((5 < *(byte *)(param_2 + 0x40c)) && ((*(byte *)(param_2 + 0x3f1) & 1) != 0)) {
    FUN_80014acc((double)FLOAT_803e8ba8);
    uVar5 = FUN_8006eea0((uint)*(byte *)(param_2 + 0x86c),*(undefined *)(param_2 + 0x8a5));
    FUN_8000bb38(param_1,uVar5);
    if (*(short *)(param_2 + 0x81a) == 0) {
      uVar5 = 0x2cf;
    }
    else {
      uVar5 = 0x25;
    }
    FUN_8000bb38(param_1,uVar5);
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
    FUN_8017082c();
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfd;
    *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) | 0x800000;
    FUN_80035f9c(param_1);
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb | 4;
    *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xef;
    *(undefined *)(param_2 + 0x800) = 0;
    iVar4 = *(int *)(param_2 + 0x7f8);
    if (iVar4 != 0) {
      if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
        FUN_80182a5c(iVar4);
      }
      else {
        FUN_800ea9f8(iVar4);
      }
      *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) =
           *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(param_2 + 0x7f8) = 0;
    }
  }
  *(char *)(param_2 + 0x40c) = *(char *)(param_2 + 0x40c) + '\x01';
  bVar3 = *(byte *)(param_2 + 0x40c);
  if (10 < bVar3) {
    bVar3 = 10;
  }
  *(byte *)(param_2 + 0x40c) = bVar3;
  *(undefined *)(param_2 + 0x8c5) = 1;
  fVar2 = FLOAT_803e8d5c;
  *(float *)(param_2 + 0x428) = FLOAT_803e8d5c;
  fVar1 = FLOAT_803e8c8c;
  *(float *)(param_2 + 0x42c) = FLOAT_803e8c8c;
  *(float *)(param_2 + 0x430) = fVar2;
  *(float *)(param_2 + 0x434) = fVar1;
  *(float *)(param_2 + 0x82c) = FLOAT_803dd2ec;
  fVar1 = *(float *)(param_2 + 0x408);
  fVar2 = FLOAT_803e8b3c;
  if ((FLOAT_803e8b3c <= fVar1) && (fVar2 = fVar1, *(float *)(param_2 + 0x404) < fVar1)) {
    fVar2 = *(float *)(param_2 + 0x404);
  }
  *(float *)(param_2 + 0x408) = fVar2;
  return 0;
}

