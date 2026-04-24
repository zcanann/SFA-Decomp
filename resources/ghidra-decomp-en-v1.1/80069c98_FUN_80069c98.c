// Function: FUN_80069c98
// Entry: 80069c98
// Size: 924 bytes

void FUN_80069c98(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  double extraout_f1;
  undefined8 uVar17;
  
  uVar17 = FUN_80286834();
  iVar10 = (int)((ulonglong)uVar17 >> 0x20);
  iVar11 = (int)uVar17;
  if ((((((iVar10 != 0) && (iVar11 != 0)) && (param_3 != 0)) &&
       ((cVar1 = *(char *)(iVar10 + 0x16), cVar1 == '\x04' || (cVar1 == '\x06')))) &&
      ((*(char *)(iVar11 + 0x16) == cVar1 &&
       ((*(char *)(param_3 + 0x16) == cVar1 && (*(short *)(iVar10 + 10) == *(short *)(iVar11 + 10)))
       )))) && ((*(short *)(iVar10 + 0xc) == *(short *)(iVar11 + 0xc) &&
                ((*(short *)(iVar10 + 10) == *(short *)(param_3 + 10) &&
                 (*(short *)(iVar10 + 0xc) == *(short *)(param_3 + 0xc))))))) {
    uVar7 = (int)((double)FLOAT_803df988 * extraout_f1) & 0xff;
    uVar8 = 0xff - uVar7 & 0xff;
    if (cVar1 == '\x04') {
      for (uVar15 = 0; (int)uVar15 < (int)(uint)*(ushort *)(iVar10 + 0xc); uVar15 = uVar15 + 1) {
        iVar5 = (uVar15 & 3) * 8;
        for (uVar16 = 0; (int)uVar16 < (int)(uint)*(ushort *)(iVar10 + 10); uVar16 = uVar16 + 1) {
          iVar6 = (uVar16 & 3) * 2;
          iVar4 = ((int)uVar16 >> 2) * 0x20;
          iVar12 = (uint)*(ushort *)(iVar10 + 10) * (uVar15 & 0xfffffffc) * 2;
          uVar2 = *(ushort *)(iVar10 + iVar6 + iVar4 + iVar5 + iVar12 + 0x60);
          uVar3 = *(ushort *)(iVar11 + iVar6 + iVar4 + iVar5 + iVar12 + 0x60);
          *(ushort *)(param_3 + iVar6 + iVar4 + iVar5 + iVar12 + 0x60) =
               (ushort)((int)(((int)(uVar7 * ((uVar2 & 0x1f) << 3 | (int)(uVar2 & 0x1c) >> 2)) >> 8)
                              + ((int)(uVar8 * ((uVar3 & 0x1f) << 3 | (int)(uVar3 & 0x1c) >> 2)) >>
                                8) & 0xf8U) >> 3) |
               (ushort)((((int)(((int)(uVar2 & 0xf800) >> 8 | (int)(uVar2 & 0xe000) >> 0xd) * uVar7)
                         >> 8) + ((int)(((int)(uVar3 & 0xf800) >> 8 | (int)(uVar3 & 0xe000) >> 0xd)
                                       * uVar8) >> 8) & 0xf8U) << 8) |
               (ushort)((((int)(uVar7 * ((int)(uVar2 & 0x7e0) >> 3 | (int)(uVar2 & 0x600) >> 9)) >>
                         8) + ((int)(uVar8 * ((int)(uVar3 & 0x7e0) >> 3 | (int)(uVar3 & 0x600) >> 9)
                                    ) >> 8) & 0xfcU) << 3);
        }
      }
    }
    else {
      for (uVar15 = 0; (int)uVar15 < (int)(uint)*(ushort *)(iVar10 + 0xc); uVar15 = uVar15 + 1) {
        iVar5 = ((int)uVar15 >> 2) * 8;
        iVar4 = (uVar15 & 3) * 8;
        for (uVar16 = 0; (int)uVar16 < (int)(uint)*(ushort *)(iVar10 + 10); uVar16 = uVar16 + 1) {
          iVar9 = (uVar16 & 3) * 2;
          iVar12 = ((int)uVar16 >> 2) * 0x40;
          iVar6 = (uint)*(ushort *)(iVar10 + 10) * iVar5 * 2;
          iVar13 = iVar10 + iVar9 + iVar12 + iVar4 + iVar6;
          iVar14 = iVar11 + iVar9 + iVar12 + iVar4 + iVar6;
          uVar2 = *(ushort *)(iVar13 + 0x80);
          uVar3 = *(ushort *)(iVar14 + 0x80);
          iVar12 = param_3 + iVar9 + iVar12 + iVar4 + 0x60;
          *(ushort *)(iVar12 + iVar6) =
               (short)((*(ushort *)(iVar13 + 0x60) & 0xff) * uVar7 >> 8) +
               (short)((*(ushort *)(iVar14 + 0x60) & 0xff) * uVar8 >> 8) & 0xff;
          *(ushort *)(iVar12 + (uint)*(ushort *)(iVar10 + 10) * iVar5 * 2 + 0x20) =
               (ushort)((((int)(((int)(uVar2 & 0xff00) >> 8) * uVar7) >> 8) +
                         ((int)(((int)(uVar3 & 0xff00) >> 8) * uVar8) >> 8) & 0xffU) << 8) |
               (short)(uVar7 * (uVar2 & 0xff) >> 8) + (short)(uVar8 * (uVar3 & 0xff) >> 8) & 0xffU;
        }
      }
    }
    FUN_80242114(param_3 + 0x60,*(int *)(param_3 + 0x44));
  }
  FUN_80286880();
  return;
}

