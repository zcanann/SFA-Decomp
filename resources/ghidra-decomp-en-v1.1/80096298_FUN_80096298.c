// Function: FUN_80096298
// Entry: 80096298
// Size: 916 bytes

void FUN_80096298(void)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = 0;
  iVar5 = 0xf;
  do {
    iVar4 = DAT_803ddeb8 + iVar2;
    if (*(short *)(iVar4 + 0x16) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803dffa4 * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x16) =
           *(short *)(iVar4 + 0x16) - (ushort)DAT_803dc070 * *(short *)(iVar4 + 0x18);
      if (*(short *)(iVar4 + 0x16) < 0) {
        *(undefined2 *)(iVar4 + 0x16) = 0;
        DAT_803ddebc = DAT_803ddebc + -1;
      }
    }
    iVar4 = DAT_803ddeb8 + iVar2 + 0x1c;
    if (*(short *)(iVar4 + 0x16) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803dffa4 * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x16) =
           *(short *)(iVar4 + 0x16) - (ushort)DAT_803dc070 * *(short *)(iVar4 + 0x18);
      if (*(short *)(iVar4 + 0x16) < 0) {
        *(undefined2 *)(iVar4 + 0x16) = 0;
        DAT_803ddebc = DAT_803ddebc + -1;
      }
    }
    iVar2 = iVar2 + 0x38;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  iVar2 = 0;
  iVar5 = 0xf;
  do {
    iVar4 = DAT_803ddea8 + iVar2;
    if (*(short *)(iVar4 + 0x14) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803dffa8 * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x14) = *(short *)(iVar4 + 0x14) + (ushort)DAT_803dc070 * -2;
      if (*(short *)(iVar4 + 0x14) < 0) {
        *(undefined2 *)(iVar4 + 0x14) = 0;
        DAT_803ddeac = DAT_803ddeac + -1;
      }
    }
    iVar4 = DAT_803ddea8 + iVar2 + 0x1c;
    if (*(short *)(iVar4 + 0x14) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803dffa8 * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x14) = *(short *)(iVar4 + 0x14) + (ushort)DAT_803dc070 * -2;
      if (*(short *)(iVar4 + 0x14) < 0) {
        *(undefined2 *)(iVar4 + 0x14) = 0;
        DAT_803ddeac = DAT_803ddeac + -1;
      }
    }
    fVar1 = FLOAT_803dff6c;
    iVar2 = iVar2 + 0x38;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  iVar2 = 0;
  iVar5 = 5;
  do {
    iVar4 = DAT_803ddeb0 + iVar2;
    if (*(float *)(iVar4 + 0x10) < fVar1) {
      *(float *)(iVar4 + 0x10) =
           *(float *)(iVar4 + 0x14) * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
      if (fVar1 <= *(float *)(iVar4 + 0x10)) {
        DAT_803ddeb4 = DAT_803ddeb4 + -1;
      }
    }
    iVar4 = DAT_803ddeb0 + iVar2 + 0x3c;
    if (*(float *)(iVar4 + 0x10) < fVar1) {
      *(float *)(iVar4 + 0x10) =
           *(float *)(iVar4 + 0x14) * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
      if (fVar1 <= *(float *)(iVar4 + 0x10)) {
        DAT_803ddeb4 = DAT_803ddeb4 + -1;
      }
    }
    iVar2 = iVar2 + 0x78;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  iVar2 = 0;
  iVar5 = 0;
  do {
    pfVar3 = (float *)(DAT_803ddea0 + iVar5);
    if (*(char *)(pfVar3 + 6) != -1) {
      iVar4 = DAT_803ddeb0 + *(char *)(pfVar3 + 6) * 0x3c;
      pfVar3[4] = FLOAT_803dffac * FLOAT_803dc074 + pfVar3[4];
      fVar1 = FLOAT_803dffb0;
      pfVar3[3] = pfVar3[3] * FLOAT_803dffb0;
      pfVar3[4] = pfVar3[4] * fVar1;
      pfVar3[5] = pfVar3[5] * fVar1;
      *pfVar3 = *pfVar3 + pfVar3[3];
      pfVar3[1] = pfVar3[1] + pfVar3[4];
      pfVar3[2] = pfVar3[2] + pfVar3[5];
      if (pfVar3[1] < *(float *)(iVar4 + 4)) {
        *(char *)(iVar4 + 0x38) = *(char *)(iVar4 + 0x38) + -1;
        *(undefined *)(pfVar3 + 6) = 0xff;
        DAT_803ddea4 = DAT_803ddea4 + -1;
        FLOAT_803dde8c = FLOAT_803dffb4;
        FUN_800959f0((double)*pfVar3,(double)*(float *)(iVar4 + 4),(double)pfVar3[2],
                     (double)FLOAT_803dff80,0,8);
      }
    }
    iVar5 = iVar5 + 0x1c;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x1e);
  return;
}

