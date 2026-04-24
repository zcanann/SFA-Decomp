// Function: FUN_800594d0
// Entry: 800594d0
// Size: 752 bytes

void FUN_800594d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined2 *param_11,int param_12)

{
  ushort uVar1;
  int iVar2;
  char cVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  short *psVar8;
  uint uVar9;
  int iVar10;
  int *piVar11;
  short *psVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 uVar14;
  
  uVar14 = FUN_80286834();
  iVar5 = (int)((ulonglong)uVar14 >> 0x20);
  uVar13 = extraout_f1;
  iVar6 = FUN_80059c3c(iVar5,(int)uVar14,param_12);
  if (iVar6 == -1) {
    *param_11 = 0xffff;
    param_11[1] = 0xffff;
    param_11[2] = 0xffff;
    param_11[3] = 0xfffe;
    *(undefined *)((int)param_11 + 9) = 0xff;
    *(undefined *)(param_11 + 4) = 0;
  }
  else {
    iVar10 = 0;
    piVar11 = &DAT_80382eac;
    iVar2 = (int)DAT_803dda6c;
    piVar7 = piVar11;
    if (0 < iVar2) {
      do {
        if ((*piVar7 != 0) && (iVar6 == *(short *)(piVar7 + 1))) goto LAB_80059554;
        piVar7 = piVar7 + 2;
        iVar10 = iVar10 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar10 = -1;
LAB_80059554:
    if (iVar10 == -1) {
      iVar10 = FUN_80059e2c(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar13 = extraout_f1_00;
    }
    (&DAT_80382eb2)[iVar10 * 8] = 1;
    psVar12 = (short *)(&DAT_80382eac)[iVar10 * 2];
    cVar3 = (char)*(undefined2 *)(DAT_80382ea0 + iVar6 * 4);
    cVar4 = (char)*(undefined2 *)(DAT_80382ea0 + iVar6 * 4 + 2);
    *param_11 = (short)iVar6;
    param_11[1] = (short)cVar3;
    param_11[2] = (short)cVar4;
    if (cVar3 != -1) {
      iVar10 = 0;
      iVar2 = (int)DAT_803dda6c;
      piVar7 = piVar11;
      if (0 < iVar2) {
        do {
          if ((*piVar7 != 0) && ((int)cVar3 == (int)*(short *)(piVar7 + 1))) goto LAB_8005960c;
          piVar7 = piVar7 + 2;
          iVar10 = iVar10 + 1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
      iVar10 = -1;
LAB_8005960c:
      if (iVar10 == -1) {
        iVar10 = FUN_80059e2c(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        uVar13 = extraout_f1_01;
      }
      (&DAT_80382eb2)[iVar10 * 8] = 1;
    }
    if (cVar4 != -1) {
      iVar10 = 0;
      iVar2 = (int)DAT_803dda6c;
      if (0 < iVar2) {
        do {
          if ((*piVar11 != 0) && ((int)cVar4 == (int)*(short *)(piVar11 + 1))) goto LAB_80059674;
          piVar11 = piVar11 + 2;
          iVar10 = iVar10 + 1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
      iVar10 = -1;
LAB_80059674:
      if (iVar10 == -1) {
        iVar10 = FUN_80059e2c(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      (&DAT_80382eb2)[iVar10 * 8] = 1;
    }
    psVar8 = (short *)(DAT_80382e9c + iVar6 * 10);
    uVar9 = *(uint *)(*(int *)(psVar12 + 6) +
                     ((iVar5 - *psVar8) + ((int)uVar14 - (int)psVar8[2]) * (int)*psVar12) * 4);
    *(byte *)(param_11 + 4) = (byte)(uVar9 >> 0x11) & 0x3f;
    *(char *)((int)param_11 + 9) = (char)(uVar9 >> 0x17);
    if (*(char *)((int)param_11 + 9) == 0xff) {
      *(undefined *)((int)param_11 + 9) = 0xff;
    }
    if (*(char *)((int)param_11 + 9) == -1) {
      param_11[3] = 0xffff;
    }
    else {
      if ((int)DAT_803ddb10 <= (int)*(char *)((int)param_11 + 9)) {
        *(char *)((int)param_11 + 9) = (char)DAT_803ddb10 + -1;
      }
      param_11[3] = (short)*(char *)(param_11 + 4) +
                    *(short *)(DAT_803ddb04 + *(char *)((int)param_11 + 9) * 2);
      uVar1 = *(ushort *)(DAT_803ddb04 + DAT_803ddb10 * 2);
      if ((int)(uint)uVar1 <= (int)(short)param_11[3]) {
        param_11[3] = uVar1 - 1;
      }
    }
  }
  FUN_80286880();
  return;
}

