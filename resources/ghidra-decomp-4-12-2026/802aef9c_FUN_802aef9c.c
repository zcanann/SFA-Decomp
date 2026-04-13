// Function: FUN_802aef9c
// Entry: 802aef9c
// Size: 396 bytes

void FUN_802aef9c(uint param_1,int param_2)

{
  float fVar1;
  short sVar2;
  int iVar3;
  
  *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xbf;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xf7;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
  *(undefined *)(param_2 + 0x40d) = 0;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xdf | 0x20;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef;
  fVar1 = FLOAT_803e8b3c;
  *(float *)(param_2 + 0x440) = FLOAT_803e8b3c;
  *(float *)(param_2 + 0x43c) = fVar1;
  if (*(short *)(param_2 + 0x81a) == 0) {
    sVar2 = 0x2d0;
  }
  else {
    sVar2 = 0x26;
  }
  FUN_8000b844(param_1,sVar2);
  if ((DAT_803df0cc != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(param_2 + 0x8b4) = 1;
    *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7 | 8;
  }
  *(undefined *)(param_2 + 0x800) = 0;
  iVar3 = *(int *)(param_2 + 0x7f8);
  if (iVar3 != 0) {
    if ((*(short *)(iVar3 + 0x46) == 0x3cf) || (*(short *)(iVar3 + 0x46) == 0x662)) {
      FUN_80182a5c(iVar3);
    }
    else {
      FUN_800ea9f8(iVar3);
    }
    *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) = *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff
    ;
    *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
    *(undefined4 *)(param_2 + 0x7f8) = 0;
  }
  if (*(float *)(param_1 + 0x28) < FLOAT_803e8dc4) {
    FUN_8000bb38(param_1,0x212);
    (**(code **)(*DAT_803dd718 + 0x10))
              ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
               (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e8b70,param_1);
  }
  return;
}

