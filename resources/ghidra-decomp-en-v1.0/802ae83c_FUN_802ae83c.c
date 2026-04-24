// Function: FUN_802ae83c
// Entry: 802ae83c
// Size: 396 bytes

void FUN_802ae83c(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  undefined4 uVar3;
  
  *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xbf;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xf7;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
  *(undefined *)(param_2 + 0x40d) = 0;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xdf | 0x20;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef;
  fVar2 = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x440) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x43c) = fVar2;
  if (*(short *)(param_2 + 0x81a) == 0) {
    uVar3 = 0x2d0;
  }
  else {
    uVar3 = 0x26;
  }
  FUN_8000b824(param_1,uVar3);
  if ((DAT_803de44c != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(param_2 + 0x8b4) = 1;
    *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7 | 8;
  }
  *(undefined *)(param_2 + 0x800) = 0;
  if (*(int *)(param_2 + 0x7f8) != 0) {
    sVar1 = *(short *)(*(int *)(param_2 + 0x7f8) + 0x46);
    if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
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
  if (*(float *)(param_1 + 0x28) < FLOAT_803e812c) {
    FUN_8000bb18(param_1,0x212);
    (**(code **)(*DAT_803dca98 + 0x10))
              ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e7ed8,param_1);
  }
  return;
}

