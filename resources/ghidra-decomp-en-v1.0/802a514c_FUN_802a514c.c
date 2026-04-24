// Function: FUN_802a514c
// Entry: 802a514c
// Size: 568 bytes

void FUN_802a514c(short *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(byte *)(iVar3 + 0x3f1) = *(byte *)(iVar3 + 0x3f1) & 0x7f;
  sVar1 = *(short *)(param_2 + 0x274);
  if ((((sVar1 != 2) && (sVar1 != 1)) && (sVar1 != 5)) && ((sVar1 != 7 && (sVar1 != 6)))) {
    *(undefined *)(iVar3 + 0x800) = 0;
    if (*(int *)(iVar3 + 0x7f8) != 0) {
      sVar1 = *(short *)(*(int *)(iVar3 + 0x7f8) + 0x46);
      if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
        FUN_80182504();
      }
      else {
        FUN_800ea774();
      }
      *(ushort *)(*(int *)(iVar3 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar3 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(iVar3 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(iVar3 + 0x7f8) = 0;
    }
  }
  if ((*(short *)(param_2 + 0x274) != 2) && (*(short *)(param_2 + 0x274) != 1)) {
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xef;
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0x7f;
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xbf;
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xf7;
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xfb;
    *(undefined *)(iVar3 + 0x40d) = 0;
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xdf;
    if ((*(byte *)(iVar3 + 0x3f1) >> 5 & 1) != 0) {
      sVar1 = *param_1;
      *(short *)(iVar3 + 0x484) = sVar1;
      *(short *)(iVar3 + 0x478) = sVar1;
      *(int *)(iVar3 + 0x494) = (int)sVar1;
      *(float *)(iVar3 + 0x284) = FLOAT_803e7ea4;
    }
    *(byte *)(iVar3 + 0x3f1) = *(byte *)(iVar3 + 0x3f1) & 0xdf;
    if (((((*(byte *)(iVar3 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(iVar3 + 0x8c8) != 'H')) &&
        (*(char *)(iVar3 + 0x8c8) != 'G')) && (iVar2 = FUN_80080204(), iVar2 == 0)) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
      *(byte *)(iVar3 + 0x3f1) = *(byte *)(iVar3 + 0x3f1) & 0xef;
    }
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) & 0xfdffffff;
  }
  if (*(short *)(param_2 + 0x274) != 2) {
    FUN_80170380(DAT_803de450,2);
    *(byte *)(iVar3 + 0x3f0) = *(byte *)(iVar3 + 0x3f0) & 0xfd;
    *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x800000;
    FUN_80035ea4(param_1);
  }
  DAT_803dc66c = 1;
  return;
}

