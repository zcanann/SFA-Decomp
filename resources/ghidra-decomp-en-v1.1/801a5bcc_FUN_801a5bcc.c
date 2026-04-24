// Function: FUN_801a5bcc
// Entry: 801a5bcc
// Size: 232 bytes

void FUN_801a5bcc(ushort *param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  float fVar4;
  float *pfVar5;
  
  pfVar5 = *(float **)(param_1 + 0x5c);
  if ((*(char *)((int)pfVar5 + 0x69) == '\x01') &&
     (iVar3 = FUN_801a584c(param_1,pfVar5), iVar3 != 0)) {
    *(undefined *)((int)pfVar5 + 0x69) = 0;
  }
  if (pfVar5[0x17] != -NAN) {
    fVar4 = pfVar5[0x16];
    uVar2 = (uint)DAT_803dc070;
    pfVar5[0x16] = (float)((int)fVar4 + uVar2);
    if ((int)pfVar5[0x17] <= (int)((int)fVar4 + uVar2)) {
      pfVar5[0x17] = -NAN;
      *(undefined *)(param_1 + 0x1b) = 0;
      param_1[3] = param_1[3] | 0x4000;
      bVar1 = true;
      goto LAB_801a5c8c;
    }
    iVar3 = (int)pfVar5[0x17] - (int)pfVar5[0x16];
    if (iVar3 < 0xff) {
      *(char *)(param_1 + 0x1b) = (char)iVar3;
    }
  }
  bVar1 = false;
LAB_801a5c8c:
  if (bVar1) {
    *(undefined *)((int)pfVar5 + 0x69) = 2;
  }
  return;
}

