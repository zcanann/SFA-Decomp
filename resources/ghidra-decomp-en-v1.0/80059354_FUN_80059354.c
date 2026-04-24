// Function: FUN_80059354
// Entry: 80059354
// Size: 752 bytes

void FUN_80059354(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined4 param_4)

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
  int iVar11;
  int *piVar12;
  short *psVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_802860d0();
  iVar5 = (int)((ulonglong)uVar14 >> 0x20);
  iVar6 = FUN_80059ac0(iVar5,(int)uVar14,param_4);
  if (iVar6 == -1) {
    *param_3 = 0xffff;
    param_3[1] = 0xffff;
    param_3[2] = 0xffff;
    param_3[3] = 0xfffe;
    *(undefined *)((int)param_3 + 9) = 0xff;
    *(undefined *)(param_3 + 4) = 0;
  }
  else {
    iVar10 = 0;
    piVar12 = &DAT_8038224c;
    iVar2 = (int)DAT_803dcdec;
    piVar7 = piVar12;
    if (0 < iVar2) {
      do {
        if ((*piVar7 != 0) && (iVar6 == *(short *)(piVar7 + 1))) goto LAB_800593d8;
        piVar7 = piVar7 + 2;
        iVar10 = iVar10 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar10 = -1;
LAB_800593d8:
    if (iVar10 == -1) {
      iVar10 = FUN_80059cb0(iVar6);
    }
    (&DAT_80382252)[iVar10 * 8] = 1;
    psVar13 = (short *)(&DAT_8038224c)[iVar10 * 2];
    cVar3 = (char)*(undefined2 *)(DAT_80382240 + iVar6 * 4);
    cVar4 = (char)*(undefined2 *)(DAT_80382240 + iVar6 * 4 + 2);
    iVar2 = (int)cVar4;
    *param_3 = (short)iVar6;
    param_3[1] = (short)cVar3;
    param_3[2] = (short)cVar4;
    if (cVar3 != -1) {
      iVar11 = 0;
      iVar10 = (int)DAT_803dcdec;
      piVar7 = piVar12;
      if (0 < iVar10) {
        do {
          if ((*piVar7 != 0) && ((int)cVar3 == (int)*(short *)(piVar7 + 1))) goto LAB_80059490;
          piVar7 = piVar7 + 2;
          iVar11 = iVar11 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
      }
      iVar11 = -1;
LAB_80059490:
      if (iVar11 == -1) {
        iVar11 = FUN_80059cb0();
      }
      (&DAT_80382252)[iVar11 * 8] = 1;
    }
    if (iVar2 != -1) {
      iVar11 = 0;
      iVar10 = (int)DAT_803dcdec;
      if (0 < iVar10) {
        do {
          if ((*piVar12 != 0) && (iVar2 == *(short *)(piVar12 + 1))) goto LAB_800594f8;
          piVar12 = piVar12 + 2;
          iVar11 = iVar11 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
      }
      iVar11 = -1;
LAB_800594f8:
      if (iVar11 == -1) {
        iVar11 = FUN_80059cb0(iVar2);
      }
      (&DAT_80382252)[iVar11 * 8] = 1;
    }
    psVar8 = (short *)(DAT_8038223c + iVar6 * 10);
    uVar9 = *(uint *)(*(int *)(psVar13 + 6) +
                     ((iVar5 - *psVar8) + ((int)uVar14 - (int)psVar8[2]) * (int)*psVar13) * 4);
    *(byte *)(param_3 + 4) = (byte)(uVar9 >> 0x11) & 0x3f;
    *(char *)((int)param_3 + 9) = (char)(uVar9 >> 0x17);
    if (*(char *)((int)param_3 + 9) == 0xff) {
      *(undefined *)((int)param_3 + 9) = 0xff;
    }
    if (*(char *)((int)param_3 + 9) == -1) {
      param_3[3] = 0xffff;
    }
    else {
      if ((int)DAT_803dce90 <= (int)*(char *)((int)param_3 + 9)) {
        *(char *)((int)param_3 + 9) = (char)DAT_803dce90 + -1;
      }
      param_3[3] = (short)*(char *)(param_3 + 4) +
                   *(short *)(DAT_803dce84 + *(char *)((int)param_3 + 9) * 2);
      uVar1 = *(ushort *)(DAT_803dce84 + DAT_803dce90 * 2);
      if ((int)(uint)uVar1 <= (int)(short)param_3[3]) {
        param_3[3] = uVar1 - 1;
      }
    }
  }
  FUN_8028611c();
  return;
}

