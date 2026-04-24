// Function: FUN_802aed2c
// Entry: 802aed2c
// Size: 520 bytes

void FUN_802aed2c(short *param_1,int param_2,int param_3)

{
  short sVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_2 + 0x8b3) == '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x47b,0);
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x47f,0);
  }
  *(float *)(param_3 + 0x2a0) = FLOAT_803e7f20;
  *(undefined2 *)(param_2 + 0x478) = *(undefined2 *)(param_2 + 0x484);
  *(float *)(param_2 + 0x844) = FLOAT_803e7ea4;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xef | 0x10;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0x7f;
  FUN_80170380(DAT_803de450,2);
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfd;
  *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) | 0x800000;
  FUN_80035ea4(param_1);
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xf7;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
  *(undefined *)(param_2 + 0x40d) = 0;
  *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xbf;
  *(undefined4 *)(param_2 + 0x488) = 0;
  *(undefined4 *)(param_2 + 0x47c) = 0;
  *(undefined4 *)(param_2 + 0x48c) = 0;
  *(undefined4 *)(param_2 + 0x480) = 0;
  DAT_803dc66c = 4;
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
  if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
    sVar1 = *param_1;
    *(short *)(param_2 + 0x484) = sVar1;
    *(short *)(param_2 + 0x478) = sVar1;
    *(int *)(param_2 + 0x494) = (int)sVar1;
    *(float *)(param_2 + 0x284) = FLOAT_803e7ea4;
  }
  *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xdf;
  if (*(float *)(param_2 + 0x838) <= FLOAT_803e7ee0) {
    if (*(short *)(param_2 + 0x81a) == 0) {
      uVar2 = 0x3ce;
    }
    else {
      uVar2 = 0x2e;
    }
    FUN_8000bb18(param_1,uVar2);
  }
  else {
    FUN_8000bb18(param_1,0x427);
  }
  return;
}

