// Function: FUN_80056d70
// Entry: 80056d70
// Size: 248 bytes

int FUN_80056d70(int param_1,int param_2,int param_3,int param_4)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  iVar6 = 0x3a;
  iVar2 = DAT_803ddae8;
  do {
    if ((*(short *)(iVar2 + 8) == param_1) && (*(short *)(iVar2 + 10) == param_2)) {
      *(char *)(iVar2 + 0xc) = *(char *)(iVar2 + 0xc) + '\x01';
      return iVar4;
    }
    iVar2 = iVar2 + 0x10;
    iVar4 = iVar4 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  iVar4 = 0;
  iVar6 = 0x1d;
  iVar2 = DAT_803ddae8;
  do {
    iVar5 = iVar4;
    if ((*(char *)(iVar2 + 0xc) == '\0') || (iVar5 = iVar4 + 1, *(char *)(iVar2 + 0x1c) == '\0'))
    break;
    iVar2 = iVar2 + 0x20;
    iVar4 = iVar4 + 2;
    iVar6 = iVar6 + -1;
    iVar5 = -1;
  } while (iVar6 != 0);
  if (iVar5 != -1) {
    pfVar3 = (float *)(DAT_803ddae8 + iVar5 * 0x10);
    *(short *)(pfVar3 + 2) = (short)((param_1 << 0x10) / (param_3 >> 6));
    *(short *)((int)pfVar3 + 10) = (short)((param_2 << 0x10) / (param_4 >> 6));
    fVar1 = FLOAT_803df84c;
    *pfVar3 = FLOAT_803df84c;
    pfVar3[1] = fVar1;
    *(char *)(pfVar3 + 3) = *(char *)(pfVar3 + 3) + '\x01';
    return iVar5;
  }
  return -1;
}

