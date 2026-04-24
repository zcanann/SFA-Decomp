// Function: FUN_8009600c
// Entry: 8009600c
// Size: 916 bytes

void FUN_8009600c(void)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = 0;
  iVar5 = 0xf;
  do {
    iVar4 = DAT_803dd238 + iVar2;
    if (*(short *)(iVar4 + 0x16) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803df324 * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x16) =
           *(short *)(iVar4 + 0x16) - (ushort)DAT_803db410 * *(short *)(iVar4 + 0x18);
      if (*(short *)(iVar4 + 0x16) < 0) {
        *(undefined2 *)(iVar4 + 0x16) = 0;
        DAT_803dd23c = DAT_803dd23c + -1;
      }
    }
    iVar4 = DAT_803dd238 + iVar2 + 0x1c;
    if (*(short *)(iVar4 + 0x16) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803df324 * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x16) =
           *(short *)(iVar4 + 0x16) - (ushort)DAT_803db410 * *(short *)(iVar4 + 0x18);
      if (*(short *)(iVar4 + 0x16) < 0) {
        *(undefined2 *)(iVar4 + 0x16) = 0;
        DAT_803dd23c = DAT_803dd23c + -1;
      }
    }
    iVar2 = iVar2 + 0x38;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  iVar2 = 0;
  iVar5 = 0xf;
  do {
    iVar4 = DAT_803dd228 + iVar2;
    if (*(short *)(iVar4 + 0x14) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803df328 * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x14) = *(short *)(iVar4 + 0x14) + (ushort)DAT_803db410 * -2;
      if (*(short *)(iVar4 + 0x14) < 0) {
        *(undefined2 *)(iVar4 + 0x14) = 0;
        DAT_803dd22c = DAT_803dd22c + -1;
      }
    }
    iVar4 = DAT_803dd228 + iVar2 + 0x1c;
    if (*(short *)(iVar4 + 0x14) != 0) {
      *(float *)(iVar4 + 0x10) = FLOAT_803df328 * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
      *(ushort *)(iVar4 + 0x14) = *(short *)(iVar4 + 0x14) + (ushort)DAT_803db410 * -2;
      if (*(short *)(iVar4 + 0x14) < 0) {
        *(undefined2 *)(iVar4 + 0x14) = 0;
        DAT_803dd22c = DAT_803dd22c + -1;
      }
    }
    fVar1 = FLOAT_803df2ec;
    iVar2 = iVar2 + 0x38;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  iVar2 = 0;
  iVar5 = 5;
  do {
    iVar4 = DAT_803dd230 + iVar2;
    if ((*(float *)(iVar4 + 0x10) < fVar1) &&
       (*(float *)(iVar4 + 0x10) =
             *(float *)(iVar4 + 0x14) * FLOAT_803db414 + *(float *)(iVar4 + 0x10),
       fVar1 <= *(float *)(iVar4 + 0x10))) {
      DAT_803dd234 = DAT_803dd234 + -1;
    }
    iVar4 = DAT_803dd230 + iVar2 + 0x3c;
    if ((*(float *)(iVar4 + 0x10) < fVar1) &&
       (*(float *)(iVar4 + 0x10) =
             *(float *)(iVar4 + 0x14) * FLOAT_803db414 + *(float *)(iVar4 + 0x10),
       fVar1 <= *(float *)(iVar4 + 0x10))) {
      DAT_803dd234 = DAT_803dd234 + -1;
    }
    iVar2 = iVar2 + 0x78;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  iVar2 = 0;
  iVar5 = 0;
  do {
    pfVar3 = (float *)(DAT_803dd220 + iVar5);
    if (*(char *)(pfVar3 + 6) != -1) {
      iVar4 = DAT_803dd230 + *(char *)(pfVar3 + 6) * 0x3c;
      pfVar3[4] = FLOAT_803df32c * FLOAT_803db414 + pfVar3[4];
      fVar1 = FLOAT_803df330;
      pfVar3[3] = pfVar3[3] * FLOAT_803df330;
      pfVar3[4] = pfVar3[4] * fVar1;
      pfVar3[5] = pfVar3[5] * fVar1;
      *pfVar3 = *pfVar3 + pfVar3[3];
      pfVar3[1] = pfVar3[1] + pfVar3[4];
      pfVar3[2] = pfVar3[2] + pfVar3[5];
      if (pfVar3[1] < *(float *)(iVar4 + 4)) {
        *(char *)(iVar4 + 0x38) = *(char *)(iVar4 + 0x38) + -1;
        *(undefined *)(pfVar3 + 6) = 0xff;
        DAT_803dd224 = DAT_803dd224 + -1;
        FLOAT_803dd20c = FLOAT_803df334;
        FUN_80095764((double)*pfVar3,(double)*(float *)(iVar4 + 4),(double)pfVar3[2],
                     (double)FLOAT_803df300,0,8);
      }
    }
    iVar5 = iVar5 + 0x1c;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x1e);
  return;
}

