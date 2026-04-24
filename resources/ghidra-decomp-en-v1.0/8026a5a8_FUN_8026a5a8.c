// Function: FUN_8026a5a8
// Entry: 8026a5a8
// Size: 1660 bytes

void FUN_8026a5a8(int param_1,short *param_2)

{
  uint *puVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  int iVar15;
  
  iVar4 = DAT_803de100;
  dataCacheBlockClearToZero(param_2);
  iVar11 = *(int *)(param_1 + 0x6a4);
  iVar7 = DAT_803de100 + 0x20;
  uVar10 = *(uint *)(param_1 + 0x6a0);
  uVar6 = iVar11 + 4U & 0x1f;
  uVar6 = (uVar10 << uVar6 | uVar10 >> 0x20 - uVar6) & 0x1f;
  if (iVar11 < 0x1d) {
    uVar3 = (uint)*(byte *)(DAT_803de100 + uVar6);
    if (uVar3 == 0xff) {
      uVar3 = iVar11 + 5;
      iVar7 = 5;
      piVar8 = (int *)(DAT_803de100 + 0x58);
LAB_8026a60c:
      if (uVar3 != 0x21) goto code_r0x8026a618;
      uVar3 = 1;
      puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
      uVar10 = *puVar1;
      piVar8 = piVar8 + 1;
      iVar11 = *piVar8;
      *(uint **)(param_1 + 0x69c) = puVar1;
      uVar6 = uVar10 >> 0x1f | uVar6 << 1;
      *(uint *)(param_1 + 0x6a0) = uVar10;
      while( true ) {
        uVar3 = uVar3 + 1;
        iVar7 = iVar7 + 1;
        if ((int)uVar6 <= iVar11) break;
        piVar8 = piVar8 + 1;
        iVar11 = *piVar8;
        uVar6 = uVar6 << 1 | (uVar10 << (uVar3 & 0x1f) | uVar10 >> 0x20 - (uVar3 & 0x1f)) & 1;
      }
LAB_8026a67c:
      *(uint *)(param_1 + 0x6a4) = uVar3;
      uVar3 = (uint)*(byte *)(uVar6 + *(int *)(iVar4 + iVar7 * 4 + 0x8c) + *(int *)(iVar4 + 0x40));
      goto LAB_8026a840;
    }
    *(uint *)(param_1 + 0x6a4) = iVar11 + (uint)*(byte *)(iVar7 + uVar6);
    goto LAB_8026a840;
  }
  if (iVar11 == 0x21) {
    puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
    uVar6 = *puVar1;
    *(uint **)(param_1 + 0x69c) = puVar1;
    uVar3 = (uint)*(byte *)(iVar4 + (uVar6 >> 0x1b));
    bVar2 = *(byte *)(iVar7 + (uVar6 >> 0x1b));
    *(uint *)(param_1 + 0x6a0) = uVar6;
    if (uVar3 != 0xff) {
      *(uint *)(param_1 + 0x6a4) = bVar2 + 1;
      goto LAB_8026a840;
    }
    iVar11 = 0x14;
    iVar7 = 5;
    do {
      iVar9 = iVar7;
      iVar7 = iVar9 + 1;
      iVar11 = iVar11 + 4;
      uVar10 = uVar6 >> 0x1f - iVar9;
    } while (*(int *)(iVar4 + iVar11 + 0x44) < (int)uVar10);
    *(int *)(param_1 + 0x6a4) = iVar9 + 2;
  }
  else {
    uVar6 = iVar11 + 4U & 0x1f;
    uVar6 = uVar10 << uVar6 | uVar10 >> 0x20 - uVar6;
    if (iVar11 != 0x20) {
      uVar3 = (uint)*(byte *)(DAT_803de100 + (uVar6 & 0x1f));
      iVar7 = iVar11 + (uint)*(byte *)(iVar7 + (uVar6 & 0x1f));
      if ((uVar3 == 0xff) || (*(int *)(param_1 + 0x6a4) = iVar7, 0x21 < iVar7)) {
        iVar9 = -iVar11 + 0x22;
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar3 = *puVar1;
        *(uint **)(param_1 + 0x69c) = puVar1;
        *(uint *)(param_1 + 0x6a0) = uVar3;
        uVar6 = uVar3 >> 0x1f | (uVar10 & ~(-1 << 0x21 - iVar11)) << 1;
        piVar8 = (int *)(iVar4 + (-iVar11 + 0x21) * 4 + 0x48);
        uVar10 = 2;
        iVar7 = *piVar8;
        while (iVar7 < (int)uVar6) {
          iVar9 = iVar9 + 1;
          piVar8 = piVar8 + 1;
          uVar6 = uVar6 * 2 + ((uVar3 << (uVar10 & 0x1f) | uVar3 >> 0x20 - (uVar10 & 0x1f)) & 1);
          uVar10 = uVar10 + 1;
          iVar7 = *piVar8;
        }
        *(uint *)(param_1 + 0x6a4) = uVar10;
        uVar3 = (uint)*(byte *)(uVar6 + *(int *)(iVar4 + iVar9 * 4 + 0x8c) + *(int *)(iVar4 + 0x40))
        ;
      }
      goto LAB_8026a840;
    }
    puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
    uVar12 = *puVar1;
    *(uint **)(param_1 + 0x69c) = puVar1;
    uVar10 = uVar12 >> 0x1c | uVar6 & 0x10;
    uVar3 = (uint)*(byte *)(iVar4 + uVar10);
    bVar2 = *(byte *)(iVar7 + uVar10);
    *(uint *)(param_1 + 0x6a0) = uVar12;
    *(uint *)(param_1 + 0x6a4) = (uint)bVar2;
    if (uVar3 != 0xff) goto LAB_8026a840;
    piVar8 = (int *)(iVar4 + 0x58);
    iVar7 = 5;
    do {
      piVar8 = piVar8 + 1;
      uVar10 = (uVar12 >> 1 | (uVar6 & 0x10) << 0x1b) >> 0x1f - iVar7;
      iVar7 = iVar7 + 1;
    } while (*piVar8 < (int)uVar10);
    *(int *)(param_1 + 0x6a4) = iVar7;
  }
  uVar3 = (uint)*(byte *)(uVar10 + *(int *)(iVar4 + iVar7 * 4 + 0x8c) + *(int *)(iVar4 + 0x40));
LAB_8026a840:
  dataCacheBlockClearToZero(param_2 + 0x10);
  sVar5 = 0;
  dataCacheBlockClearToZero(param_2 + 0x20);
  if (uVar3 != 0) {
    iVar7 = *(int *)(param_1 + 0x6a4);
    iVar4 = *(int *)(param_1 + 0x6a0);
    iVar11 = uVar3 - (0x21 - iVar7);
    if (iVar11 < 1) {
      *(uint *)(param_1 + 0x6a4) = iVar7 + uVar3;
      sVar5 = (short)((uint)(iVar4 << iVar7 + -1) >> 0x20 - uVar3);
    }
    else {
      puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
      uVar6 = *puVar1;
      *(uint *)(param_1 + 0x6a0) = uVar6;
      *(uint **)(param_1 + 0x69c) = puVar1;
      *(int *)(param_1 + 0x6a4) = iVar11 + 1;
      sVar5 = (short)((uVar6 >> 0x21 - iVar7) + (iVar4 << iVar7 + -1) >> 0x20 - uVar3);
    }
    iVar4 = countLeadingZeros((int)sVar5);
    if ((int)(0x20 - uVar3) < iVar4) {
      sVar5 = (short)(-1 << uVar3) + sVar5 + 1;
    }
  }
  dataCacheBlockClearToZero(param_2 + 0x30);
  sVar5 = *(short *)(param_1 + 0x684) + sVar5;
  *(short *)(param_1 + 0x684) = sVar5;
  *param_2 = sVar5;
  iVar4 = DAT_803de160;
  iVar11 = DAT_803de160 + 0x20;
  uVar10 = *(uint *)(param_1 + 0x6a0);
  uVar6 = *(uint *)(param_1 + 0x6a4);
  for (iVar7 = 1; uVar3 = uVar6, iVar7 < 0x40; iVar7 = iVar7 + 1) {
    uVar3 = uVar6 + 4 & 0x1f;
    uVar12 = (uVar10 << uVar3 | uVar10 >> 0x20 - uVar3) & 0x1f;
    if ((int)uVar6 < 0x1d) {
      uVar14 = (uint)*(byte *)(iVar4 + uVar12);
      if (uVar14 == 0xff) {
        uVar3 = uVar6 + 5;
        iVar9 = 5;
        piVar8 = (int *)(iVar4 + 0x58);
LAB_8026a950:
        if (uVar3 != 0x21) goto code_r0x8026a95c;
        uVar3 = 1;
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar10 = *puVar1;
        piVar8 = piVar8 + 1;
        iVar13 = *piVar8;
        *(uint **)(param_1 + 0x69c) = puVar1;
        uVar12 = uVar10 >> 0x1f | uVar12 << 1;
        while( true ) {
          uVar3 = uVar3 + 1;
          iVar9 = iVar9 + 1;
          if ((int)uVar12 <= iVar13) break;
          piVar8 = piVar8 + 1;
          iVar13 = *piVar8;
          uVar12 = uVar12 << 1 | (uVar10 << (uVar3 & 0x1f) | uVar10 >> 0x20 - (uVar3 & 0x1f)) & 1;
        }
LAB_8026a9bc:
        uVar14 = (uint)*(byte *)(uVar12 + *(int *)(iVar4 + iVar9 * 4 + 0x8c) +
                                          *(int *)(iVar4 + 0x40));
        goto LAB_8026ab60;
      }
      uVar3 = uVar6 + *(byte *)(iVar11 + uVar12);
    }
    else if (uVar6 == 0x21) {
      puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
      uVar10 = *puVar1;
      *(uint **)(param_1 + 0x69c) = puVar1;
      uVar14 = (uint)*(byte *)(iVar4 + (uVar10 >> 0x1b));
      uVar3 = *(byte *)(iVar11 + (uVar10 >> 0x1b)) + 1;
      if (uVar14 == 0xff) {
        iVar13 = 0x14;
        iVar9 = 5;
        do {
          iVar15 = iVar9;
          iVar13 = iVar13 + 4;
          uVar6 = uVar10 >> 0x1f - iVar15;
          iVar9 = iVar15 + 1;
        } while (*(int *)(iVar4 + iVar13 + 0x44) < (int)uVar6);
        uVar3 = iVar15 + 2;
        uVar14 = (uint)*(byte *)(uVar6 + *(int *)(iVar4 + iVar13 + 0x8c) + *(int *)(iVar4 + 0x40));
      }
    }
    else {
      uVar3 = uVar6 + 4 & 0x1f;
      uVar12 = uVar10 << uVar3 | uVar10 >> 0x20 - uVar3;
      if (uVar6 == 0x20) {
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar10 = *puVar1;
        *(uint **)(param_1 + 0x69c) = puVar1;
        uVar6 = uVar10 >> 0x1c | uVar12 & 0x10;
        uVar14 = (uint)*(byte *)(iVar4 + uVar6);
        uVar3 = (uint)*(byte *)(iVar11 + uVar6);
        if (uVar14 == 0xff) {
          piVar8 = (int *)(iVar4 + 0x58);
          uVar3 = 5;
          do {
            piVar8 = piVar8 + 1;
            uVar6 = (uVar10 >> 1 | (uVar12 & 0x10) << 0x1b) >> 0x1f - uVar3;
            uVar3 = uVar3 + 1;
          } while (*piVar8 < (int)uVar6);
          uVar14 = (uint)*(byte *)(uVar6 + *(int *)(iVar4 + uVar3 * 4 + 0x8c) +
                                           *(int *)(iVar4 + 0x40));
        }
      }
      else {
        uVar14 = (uint)*(byte *)(iVar4 + (uVar12 & 0x1f));
        uVar3 = uVar6 + *(byte *)(iVar11 + (uVar12 & 0x1f));
        if ((uVar14 == 0xff) || (0x21 < (int)uVar3)) {
          uVar3 = uVar10 & ~(-1 << 0x21 - uVar6);
          iVar13 = -uVar6 + 0x22;
          puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
          uVar10 = *puVar1;
          *(uint **)(param_1 + 0x69c) = puVar1;
          uVar12 = uVar10 >> 0x1f | uVar3 << 1;
          piVar8 = (int *)(iVar4 + (-uVar6 + 0x21) * 4 + 0x48);
          uVar3 = 2;
          iVar9 = *piVar8;
          while (iVar9 < (int)uVar12) {
            iVar13 = iVar13 + 1;
            piVar8 = piVar8 + 1;
            uVar12 = uVar12 * 2 + ((uVar10 << (uVar3 & 0x1f) | uVar10 >> 0x20 - (uVar3 & 0x1f)) & 1)
            ;
            uVar3 = uVar3 + 1;
            iVar9 = *piVar8;
          }
          uVar14 = (uint)*(byte *)(uVar12 + *(int *)(iVar4 + iVar13 * 4 + 0x8c) +
                                            *(int *)(iVar4 + 0x40));
        }
      }
    }
LAB_8026ab60:
    uVar6 = uVar14 & 0xf;
    if (uVar6 == 0) {
      if ((int)uVar14 >> 4 != 0xf) break;
      iVar7 = iVar7 + 0xf;
    }
    else {
      iVar7 = iVar7 + ((int)uVar14 >> 4);
      iVar15 = 0x21 - uVar3;
      iVar13 = uVar6 - iVar15;
      iVar9 = uVar3 - 1;
      if (iVar13 < 1) {
        uVar3 = uVar3 + uVar6;
        uVar12 = (uVar10 << iVar9) >> 0x20 - uVar6;
      }
      else {
        iVar9 = uVar10 << iVar9;
        puVar1 = (uint *)(*(int *)(param_1 + 0x69c) + 4);
        uVar10 = *puVar1;
        uVar3 = iVar13 + 1;
        *(uint **)(param_1 + 0x69c) = puVar1;
        uVar12 = (uVar10 >> iVar15) + iVar9 >> 0x20 - uVar6;
      }
      iVar9 = countLeadingZeros(uVar12);
      if ((int)(0x20 - uVar6) < iVar9) {
        uVar12 = (-1 << uVar6) + uVar12 + 1;
      }
      param_2[(byte)(&DAT_802c2628)[iVar7]] = (short)uVar12;
    }
    uVar6 = uVar3;
  }
  *(uint *)(param_1 + 0x6a4) = uVar3;
  *(uint *)(param_1 + 0x6a0) = uVar10;
  return;
code_r0x8026a618:
  piVar8 = piVar8 + 1;
  uVar6 = uVar6 << 1 | (uVar10 << (uVar3 & 0x1f) | uVar10 >> 0x20 - (uVar3 & 0x1f)) & 1;
  uVar3 = uVar3 + 1;
  iVar7 = iVar7 + 1;
  if ((int)uVar6 <= *piVar8) goto LAB_8026a67c;
  goto LAB_8026a60c;
code_r0x8026a95c:
  piVar8 = piVar8 + 1;
  uVar12 = uVar12 << 1 | (uVar10 << (uVar3 & 0x1f) | uVar10 >> 0x20 - (uVar3 & 0x1f)) & 1;
  uVar3 = uVar3 + 1;
  iVar9 = iVar9 + 1;
  if ((int)uVar12 <= *piVar8) goto LAB_8026a9bc;
  goto LAB_8026a950;
}

