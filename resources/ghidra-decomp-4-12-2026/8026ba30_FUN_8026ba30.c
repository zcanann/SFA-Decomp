// Function: FUN_8026ba30
// Entry: 8026ba30
// Size: 1704 bytes

void FUN_8026ba30(int param_1,short *param_2)

{
  uint *puVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  short sVar6;
  int *piVar5;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  
  iVar4 = DAT_803dedc0;
  dataCacheBlockClearToZero(param_2);
  iVar10 = *(int *)(param_1 + 0x6a4);
  iVar8 = DAT_803dedc0 + 0x20;
  uVar9 = *(uint *)(param_1 + 0x6a0);
  uVar7 = iVar10 + 4U & 0x1f;
  uVar7 = (uVar9 << uVar7 | uVar9 >> 0x20 - uVar7) & 0x1f;
  if (iVar10 < 0x1d) {
    uVar3 = (uint)*(byte *)(DAT_803dedc0 + uVar7);
    if (uVar3 == 0xff) {
      uVar3 = iVar10 + 5;
      iVar8 = 5;
      piVar5 = (int *)(DAT_803dedc0 + 0x58);
LAB_8026ba90:
      if (uVar3 != 0x21) goto code_r0x8026ba9c;
      uVar3 = 1;
      puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
      uVar9 = *puVar1;
      piVar5 = piVar5 + 1;
      iVar10 = *piVar5;
      *(uint **)(param_1 + 0x69c) = puVar1;
      uVar7 = uVar9 >> 0x1f | uVar7 << 1;
      *(uint *)(param_1 + 0x6a0) = uVar9;
      while( true ) {
        uVar3 = uVar3 + 1;
        iVar8 = iVar8 + 1;
        if ((int)uVar7 <= iVar10) break;
        piVar5 = piVar5 + 1;
        iVar10 = *piVar5;
        uVar7 = uVar7 << 1 | (uVar9 << (uVar3 & 0x1f) | uVar9 >> 0x20 - (uVar3 & 0x1f)) & 1;
      }
LAB_8026bb00:
      *(uint *)(param_1 + 0x6a4) = uVar3;
      uVar3 = (uint)*(byte *)(uVar7 + *(int *)(iVar4 + iVar8 * 4 + 0x8c) + *(int *)(iVar4 + 0x40));
      goto LAB_8026bcc4;
    }
    *(uint *)(param_1 + 0x6a4) = iVar10 + (uint)*(byte *)(iVar8 + uVar7);
    goto LAB_8026bcc4;
  }
  if (iVar10 == 0x21) {
    puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
    uVar7 = *puVar1;
    *(uint **)(param_1 + 0x69c) = puVar1;
    uVar3 = (uint)*(byte *)(iVar4 + (uVar7 >> 0x1b));
    bVar2 = *(byte *)(iVar8 + (uVar7 >> 0x1b));
    *(uint *)(param_1 + 0x6a0) = uVar7;
    if (uVar3 != 0xff) {
      *(uint *)(param_1 + 0x6a4) = bVar2 + 1;
      goto LAB_8026bcc4;
    }
    iVar10 = 0x14;
    iVar8 = 5;
    do {
      iVar12 = iVar8;
      iVar8 = iVar12 + 1;
      iVar10 = iVar10 + 4;
      uVar9 = uVar7 >> 0x1f - iVar12;
    } while (*(int *)(iVar4 + iVar10 + 0x44) < (int)uVar9);
    *(int *)(param_1 + 0x6a4) = iVar12 + 2;
  }
  else {
    uVar7 = iVar10 + 4U & 0x1f;
    uVar7 = uVar9 << uVar7 | uVar9 >> 0x20 - uVar7;
    if (iVar10 != 0x20) {
      uVar3 = (uint)*(byte *)(DAT_803dedc0 + (uVar7 & 0x1f));
      iVar8 = iVar10 + (uint)*(byte *)(iVar8 + (uVar7 & 0x1f));
      if ((uVar3 == 0xff) || (*(int *)(param_1 + 0x6a4) = iVar8, 0x21 < iVar8)) {
        iVar12 = -iVar10 + 0x22;
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar3 = *puVar1;
        *(uint **)(param_1 + 0x69c) = puVar1;
        *(uint *)(param_1 + 0x6a0) = uVar3;
        uVar7 = uVar3 >> 0x1f | (uVar9 & ~(-1 << 0x21 - iVar10)) << 1;
        piVar5 = (int *)(iVar4 + (-iVar10 + 0x21) * 4 + 0x48);
        uVar9 = 2;
        iVar8 = *piVar5;
        while (iVar8 < (int)uVar7) {
          iVar12 = iVar12 + 1;
          piVar5 = piVar5 + 1;
          uVar7 = uVar7 * 2 + ((uVar3 << (uVar9 & 0x1f) | uVar3 >> 0x20 - (uVar9 & 0x1f)) & 1);
          uVar9 = uVar9 + 1;
          iVar8 = *piVar5;
        }
        *(uint *)(param_1 + 0x6a4) = uVar9;
        uVar3 = (uint)*(byte *)(uVar7 + *(int *)(iVar4 + iVar12 * 4 + 0x8c) + *(int *)(iVar4 + 0x40)
                               );
      }
      goto LAB_8026bcc4;
    }
    puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
    uVar11 = *puVar1;
    *(uint **)(param_1 + 0x69c) = puVar1;
    uVar9 = uVar11 >> 0x1c | uVar7 & 0x10;
    uVar3 = (uint)*(byte *)(iVar4 + uVar9);
    bVar2 = *(byte *)(iVar8 + uVar9);
    *(uint *)(param_1 + 0x6a0) = uVar11;
    *(uint *)(param_1 + 0x6a4) = (uint)bVar2;
    if (uVar3 != 0xff) goto LAB_8026bcc4;
    piVar5 = (int *)(iVar4 + 0x58);
    iVar8 = 5;
    do {
      piVar5 = piVar5 + 1;
      uVar9 = (uVar11 >> 1 | (uVar7 & 0x10) << 0x1b) >> 0x1f - iVar8;
      iVar8 = iVar8 + 1;
    } while (*piVar5 < (int)uVar9);
    *(int *)(param_1 + 0x6a4) = iVar8;
  }
  uVar3 = (uint)*(byte *)(uVar9 + *(int *)(iVar4 + iVar8 * 4 + 0x8c) + *(int *)(iVar4 + 0x40));
LAB_8026bcc4:
  dataCacheBlockClearToZero(param_2 + 0x10);
  sVar6 = 0;
  dataCacheBlockClearToZero(param_2 + 0x20);
  if (uVar3 != 0) {
    iVar8 = *(int *)(param_1 + 0x6a4);
    iVar4 = *(int *)(param_1 + 0x6a0);
    iVar10 = uVar3 - (0x21 - iVar8);
    if (iVar10 < 1) {
      *(uint *)(param_1 + 0x6a4) = iVar8 + uVar3;
      sVar6 = (short)((uint)(iVar4 << iVar8 + -1) >> 0x20 - uVar3);
    }
    else {
      puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
      uVar7 = *puVar1;
      *(uint *)(param_1 + 0x6a0) = uVar7;
      *(uint **)(param_1 + 0x69c) = puVar1;
      *(int *)(param_1 + 0x6a4) = iVar10 + 1;
      sVar6 = (short)((uVar7 >> 0x21 - iVar8) + (iVar4 << iVar8 + -1) >> 0x20 - uVar3);
    }
    iVar4 = countLeadingZeros((int)sVar6);
    if ((int)(0x20 - uVar3) < iVar4) {
      sVar6 = (short)(-1 << uVar3) + sVar6 + 1;
    }
  }
  dataCacheBlockClearToZero(param_2 + 0x30);
  sVar6 = *(short *)(param_1 + 0x690) + sVar6;
  *(short *)(param_1 + 0x690) = sVar6;
  iVar4 = 1;
  *param_2 = sVar6;
  do {
    iVar8 = DAT_803dee20;
    if (0x3f < iVar4) {
      return;
    }
    iVar12 = *(int *)(param_1 + 0x6a4);
    iVar10 = DAT_803dee20 + 0x20;
    uVar9 = *(uint *)(param_1 + 0x6a0);
    uVar7 = iVar12 + 4U & 0x1f;
    uVar7 = (uVar9 << uVar7 | uVar9 >> 0x20 - uVar7) & 0x1f;
    if (iVar12 < 0x1d) {
      uVar3 = (uint)*(byte *)(DAT_803dee20 + uVar7);
      if (uVar3 == 0xff) {
        uVar3 = iVar12 + 5;
        iVar10 = 5;
        piVar5 = (int *)(DAT_803dee20 + 0x58);
LAB_8026bdd8:
        if (uVar3 != 0x21) goto code_r0x8026bde4;
        uVar3 = 1;
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar9 = *puVar1;
        piVar5 = piVar5 + 1;
        iVar12 = *piVar5;
        *(uint **)(param_1 + 0x69c) = puVar1;
        uVar7 = uVar9 >> 0x1f | uVar7 << 1;
        *(uint *)(param_1 + 0x6a0) = uVar9;
        while( true ) {
          uVar3 = uVar3 + 1;
          iVar10 = iVar10 + 1;
          if ((int)uVar7 <= iVar12) break;
          piVar5 = piVar5 + 1;
          iVar12 = *piVar5;
          uVar7 = uVar7 << 1 | (uVar9 << (uVar3 & 0x1f) | uVar9 >> 0x20 - (uVar3 & 0x1f)) & 1;
        }
LAB_8026be48:
        *(uint *)(param_1 + 0x6a4) = uVar3;
        uVar3 = (uint)*(byte *)(uVar7 + *(int *)(iVar8 + iVar10 * 4 + 0x8c) + *(int *)(iVar8 + 0x40)
                               );
        goto LAB_8026c00c;
      }
      *(uint *)(param_1 + 0x6a4) = iVar12 + (uint)*(byte *)(iVar10 + uVar7);
    }
    else if (iVar12 == 0x21) {
      puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
      uVar7 = *puVar1;
      *(uint **)(param_1 + 0x69c) = puVar1;
      uVar3 = (uint)*(byte *)(iVar8 + (uVar7 >> 0x1b));
      bVar2 = *(byte *)(iVar10 + (uVar7 >> 0x1b));
      *(uint *)(param_1 + 0x6a0) = uVar7;
      if (uVar3 == 0xff) {
        iVar12 = 0x14;
        iVar10 = 5;
        do {
          iVar13 = iVar10;
          iVar10 = iVar13 + 1;
          iVar12 = iVar12 + 4;
          uVar9 = uVar7 >> 0x1f - iVar13;
        } while (*(int *)(iVar8 + iVar12 + 0x44) < (int)uVar9);
        *(int *)(param_1 + 0x6a4) = iVar13 + 2;
LAB_8026bf08:
        uVar3 = (uint)*(byte *)(uVar9 + *(int *)(iVar8 + iVar10 * 4 + 0x8c) + *(int *)(iVar8 + 0x40)
                               );
      }
      else {
        *(uint *)(param_1 + 0x6a4) = bVar2 + 1;
      }
    }
    else {
      uVar7 = iVar12 + 4U & 0x1f;
      uVar7 = uVar9 << uVar7 | uVar9 >> 0x20 - uVar7;
      if (iVar12 == 0x20) {
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar11 = *puVar1;
        *(uint **)(param_1 + 0x69c) = puVar1;
        uVar9 = uVar11 >> 0x1c | uVar7 & 0x10;
        uVar3 = (uint)*(byte *)(iVar8 + uVar9);
        bVar2 = *(byte *)(iVar10 + uVar9);
        *(uint *)(param_1 + 0x6a0) = uVar11;
        *(uint *)(param_1 + 0x6a4) = (uint)bVar2;
        if (uVar3 == 0xff) {
          piVar5 = (int *)(iVar8 + 0x58);
          iVar10 = 5;
          do {
            piVar5 = piVar5 + 1;
            uVar9 = (uVar11 >> 1 | (uVar7 & 0x10) << 0x1b) >> 0x1f - iVar10;
            iVar10 = iVar10 + 1;
          } while (*piVar5 < (int)uVar9);
          *(int *)(param_1 + 0x6a4) = iVar10;
          goto LAB_8026bf08;
        }
      }
      else {
        uVar3 = (uint)*(byte *)(DAT_803dee20 + (uVar7 & 0x1f));
        iVar10 = iVar12 + (uint)*(byte *)(iVar10 + (uVar7 & 0x1f));
        if ((uVar3 == 0xff) || (*(int *)(param_1 + 0x6a4) = iVar10, 0x21 < iVar10)) {
          iVar13 = -iVar12 + 0x22;
          puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
          uVar3 = *puVar1;
          *(uint **)(param_1 + 0x69c) = puVar1;
          *(uint *)(param_1 + 0x6a0) = uVar3;
          uVar7 = uVar3 >> 0x1f | (uVar9 & ~(-1 << 0x21 - iVar12)) << 1;
          piVar5 = (int *)(iVar8 + (-iVar12 + 0x21) * 4 + 0x48);
          uVar9 = 2;
          iVar10 = *piVar5;
          while (iVar10 < (int)uVar7) {
            iVar13 = iVar13 + 1;
            piVar5 = piVar5 + 1;
            uVar7 = uVar7 * 2 + ((uVar3 << (uVar9 & 0x1f) | uVar3 >> 0x20 - (uVar9 & 0x1f)) & 1);
            uVar9 = uVar9 + 1;
            iVar10 = *piVar5;
          }
          *(uint *)(param_1 + 0x6a4) = uVar9;
          uVar3 = (uint)*(byte *)(uVar7 + *(int *)(iVar8 + iVar13 * 4 + 0x8c) +
                                          *(int *)(iVar8 + 0x40));
        }
      }
    }
LAB_8026c00c:
    uVar7 = uVar3 & 0xf;
    if (uVar7 == 0) {
      if ((int)uVar3 >> 4 != 0xf) {
        return;
      }
      iVar4 = iVar4 + 0xf;
    }
    else {
      iVar4 = iVar4 + ((int)uVar3 >> 4);
      iVar10 = *(int *)(param_1 + 0x6a4);
      iVar8 = *(int *)(param_1 + 0x6a0);
      iVar12 = uVar7 - (0x21 - iVar10);
      if (iVar12 < 1) {
        *(uint *)(param_1 + 0x6a4) = iVar10 + uVar7;
        uVar9 = (uint)(iVar8 << iVar10 + -1) >> 0x20 - uVar7;
      }
      else {
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar9 = *puVar1;
        *(uint *)(param_1 + 0x6a0) = uVar9;
        *(uint **)(param_1 + 0x69c) = puVar1;
        *(int *)(param_1 + 0x6a4) = iVar12 + 1;
        uVar9 = (uVar9 >> 0x21 - iVar10) + (iVar8 << iVar10 + -1) >> 0x20 - uVar7;
      }
      iVar8 = countLeadingZeros(uVar9);
      if ((int)(0x20 - uVar7) < iVar8) {
        uVar9 = (-1 << uVar7) + uVar9 + 1;
      }
      param_2[(byte)(&DAT_802c2da8)[iVar4]] = (short)uVar9;
    }
    iVar4 = iVar4 + 1;
  } while( true );
code_r0x8026ba9c:
  piVar5 = piVar5 + 1;
  uVar7 = uVar7 << 1 | (uVar9 << (uVar3 & 0x1f) | uVar9 >> 0x20 - (uVar3 & 0x1f)) & 1;
  uVar3 = uVar3 + 1;
  iVar8 = iVar8 + 1;
  if ((int)uVar7 <= *piVar5) goto LAB_8026bb00;
  goto LAB_8026ba90;
code_r0x8026bde4:
  piVar5 = piVar5 + 1;
  uVar7 = uVar7 << 1 | (uVar9 << (uVar3 & 0x1f) | uVar9 >> 0x20 - (uVar3 & 0x1f)) & 1;
  uVar3 = uVar3 + 1;
  iVar10 = iVar10 + 1;
  if ((int)uVar7 <= *piVar5) goto LAB_8026be48;
  goto LAB_8026bdd8;
}

