// Function: FUN_801aa90c
// Entry: 801aa90c
// Size: 2860 bytes

/* WARNING: Removing unreachable block (ram,0x801ab418) */

void FUN_801aa90c(void)

{
  bool bVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  char cVar6;
  undefined4 uVar5;
  int iVar7;
  int iVar8;
  short unaff_r26;
  short unaff_r27;
  int unaff_r28;
  byte bVar9;
  int *piVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  double in_f31;
  int local_58;
  float local_54 [2];
  undefined auStack76 [12];
  double local_40;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  psVar2 = (short *)FUN_802860d0();
  piVar10 = *(int **)(psVar2 + 0x5c);
  if (((&DAT_80323408)[*(byte *)(piVar10 + 4)] & 1) == 0) {
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
  }
  iVar7 = piVar10[2];
  if (iVar7 != 0) {
    dVar12 = (double)FUN_8014c5d0(iVar7);
    if ((double)FLOAT_803e4680 < dVar12) {
      iVar7 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar7 + 0x4c) + 0x18));
      if (iVar7 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (bVar1) {
      iVar7 = piVar10[3];
      dVar12 = (double)FUN_8014c5d0(iVar7);
      if ((double)FLOAT_803e4680 < dVar12) {
        iVar7 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar7 + 0x4c) + 0x18));
        if (iVar7 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (!bVar1) goto LAB_801aab64;
      dVar12 = (double)FUN_8002166c(piVar10[1] + 0x18,piVar10[3] + 0x18);
      dVar13 = (double)FUN_8002166c(piVar10[1] + 0x18,piVar10[2] + 0x18);
      if (dVar12 <= dVar13) {
        iVar7 = piVar10[3];
        iVar8 = piVar10[2];
      }
      else {
        iVar7 = piVar10[2];
        iVar8 = piVar10[3];
      }
      dVar12 = (double)FUN_8002166c(psVar2 + 0xc,piVar10[1] + 0x18);
      if (((((double)FLOAT_803e4684 <= dVar12) &&
           (iVar3 = FUN_80296118(piVar10[1]), iVar3 != piVar10[2])) &&
          (iVar3 = FUN_80296118(piVar10[1]), iVar3 != piVar10[3])) ||
         (iVar3 = FUN_80295cd4(piVar10[1]), iVar3 != 0)) {
        for (bVar9 = 0; bVar9 < 2; bVar9 = bVar9 + 1) {
          dVar12 = (double)FUN_8002166c(psVar2 + 0xc,piVar10[bVar9 + 2] + 0x18);
          local_54[bVar9] = (float)dVar12;
          FUN_8014c66c(piVar10[bVar9 + 2],psVar2);
        }
        in_f31 = (double)local_54[1];
        if (in_f31 <= (double)local_54[0]) {
          unaff_r28 = piVar10[3];
        }
        else {
          unaff_r28 = piVar10[2];
          in_f31 = (double)local_54[0];
        }
      }
      else {
        iVar3 = FUN_80296118(piVar10[1]);
        unaff_r28 = iVar8;
        if (iVar3 == iVar8) {
          unaff_r28 = iVar7;
          iVar7 = iVar8;
        }
        FUN_8014c66c(iVar7,piVar10[1]);
        FUN_8014c66c(unaff_r28,psVar2);
        in_f31 = (double)FUN_8002166c(psVar2 + 0xc,unaff_r28 + 0x18);
      }
    }
    else {
LAB_801aab64:
      iVar7 = piVar10[2];
      dVar12 = (double)FUN_8014c5d0(iVar7);
      if ((double)FLOAT_803e4680 < dVar12) {
        iVar7 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar7 + 0x4c) + 0x18));
        if (iVar7 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      unaff_r28 = 0;
      if (bVar1) {
        unaff_r28 = piVar10[2];
      }
      iVar7 = piVar10[3];
      dVar12 = (double)FUN_8014c5d0(iVar7);
      if ((double)FLOAT_803e4680 < dVar12) {
        iVar7 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar7 + 0x4c) + 0x18));
        if (iVar7 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (bVar1) {
        unaff_r28 = piVar10[3];
      }
      if (unaff_r28 == 0) {
        unaff_r28 = piVar10[1];
        in_f31 = (double)FLOAT_803e4674;
      }
      else {
        dVar12 = (double)FUN_8002166c(piVar10[1] + 0x18,unaff_r28 + 0x18);
        dVar13 = (double)FUN_8002166c(psVar2 + 0xc,unaff_r28 + 0x18);
        if (((dVar13 < dVar12) && (iVar7 = FUN_80296118(piVar10[1]), iVar7 != unaff_r28)) ||
           (iVar7 = FUN_80295cd4(piVar10[1]), iVar7 != 0)) {
          FUN_8014c66c(unaff_r28,psVar2);
        }
        else {
          FUN_8014c66c(unaff_r28,piVar10[1]);
        }
        in_f31 = (double)FUN_8002166c(psVar2 + 0xc,unaff_r28 + 0x18);
      }
    }
    unaff_r27 = FUN_800217c0(-(double)(*(float *)(unaff_r28 + 0xc) - *(float *)(psVar2 + 6)),
                             -(double)(*(float *)(unaff_r28 + 0x14) - *(float *)(psVar2 + 10)));
    unaff_r26 = *psVar2 - unaff_r27;
    if (0x8000 < unaff_r26) {
      unaff_r26 = unaff_r26 + 1;
    }
    if (unaff_r26 < -0x8000) {
      unaff_r26 = unaff_r26 + -1;
    }
    if (unaff_r26 < 0x1001) {
      if (unaff_r26 < -0x1000) {
        *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 2;
      }
      else {
        *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) & 0xfd;
      }
    }
    else {
      *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 2;
    }
  }
  if ((*(byte *)(piVar10 + 4) < 0xc) &&
     (piVar10[5] = (int)((float)piVar10[5] - FLOAT_803db414), (float)piVar10[5] < FLOAT_803e4680)) {
    uVar4 = FUN_800221a0(0xb4,300);
    local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    piVar10[5] = (int)(float)(local_40 - DOUBLE_803e46a0);
    FUN_8000bb18(psVar2,0x134);
  }
  switch(*(undefined *)(piVar10 + 4)) {
  case 0:
    iVar7 = FUN_8001ffb4(9);
    if (iVar7 == 0) {
      cVar6 = FUN_8002e04c();
      if (cVar6 != '\0') {
        uVar5 = FUN_8002bdf4(0x20,0x6f1);
        iVar7 = FUN_8002df90(uVar5,5,0xffffffff,0xffffffff,*(undefined4 *)(psVar2 + 0x18));
        *piVar10 = iVar7;
        FUN_80037d2c(psVar2,*piVar10,0);
      }
      iVar7 = FUN_8002b9ec();
      piVar10[1] = iVar7;
      iVar7 = FUN_8002e0b4(0x45d7d);
      piVar10[2] = iVar7;
      iVar7 = FUN_8002e0b4(0x45d7f);
      piVar10[3] = iVar7;
      *(undefined *)(piVar10 + 4) = 1;
      uVar4 = FUN_800221a0(0xb4,300);
      local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      piVar10[5] = (int)(float)(local_40 - DOUBLE_803e46a0);
    }
    else {
      *(undefined *)(piVar10 + 4) = 0xe;
    }
    break;
  case 1:
    if ((FLOAT_803e467c < *(float *)(psVar2 + 0x4c)) && (*(float *)(psVar2 + 0x4c) < FLOAT_803e4688)
       ) {
      if (unaff_r26 < 0x401) {
        if (unaff_r26 < -0x400) {
          local_40 = (double)(longlong)(int)(FLOAT_803e468c * FLOAT_803db414);
          *psVar2 = *psVar2 + (short)(int)(FLOAT_803e468c * FLOAT_803db414);
        }
        else {
          *psVar2 = unaff_r27;
        }
      }
      else {
        local_40 = (double)(longlong)(int)(FLOAT_803e468c * FLOAT_803db414);
        *psVar2 = *psVar2 - (short)(int)(FLOAT_803e468c * FLOAT_803db414);
      }
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      FUN_801aa878(in_f31,piVar10,unaff_r28);
    }
    break;
  case 2:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      if ((double)FLOAT_803e4678 <= in_f31) {
        *(undefined *)(piVar10 + 4) = 3;
      }
      else {
        *(undefined *)(piVar10 + 4) = 4;
      }
    }
    break;
  case 3:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 4;
    }
    break;
  case 4:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      FUN_801aa878(in_f31,piVar10,unaff_r28);
    }
    break;
  case 5:
    if (*(short *)(unaff_r28 + 0xa0) != 0x19) {
      *(undefined *)(piVar10 + 4) = 7;
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 6;
    }
    break;
  case 6:
    if (*(short *)(unaff_r28 + 0xa0) != 0x19) {
      *(undefined *)(piVar10 + 4) = 7;
    }
    break;
  case 7:
    if ((*(short *)(unaff_r28 + 0xa0) != 0x18) || (*(float *)(unaff_r28 + 0x98) <= FLOAT_803e467c))
    {
      if (*(short *)(unaff_r28 + 0xa0) == 0x19) {
        *(undefined *)(piVar10 + 4) = 5;
      }
      else if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
        FUN_801aa878(in_f31,piVar10,unaff_r28);
      }
    }
    else {
      *(undefined *)(piVar10 + 4) = 8;
    }
    break;
  case 8:
    bVar1 = *(short *)(unaff_r28 + 0xa0) != 0x18;
    if ((bVar1) || ((!bVar1 && (*(float *)(unaff_r28 + 0x98) < FLOAT_803e467c)))) {
      *(undefined *)(piVar10 + 4) = 10;
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 9;
    }
    break;
  case 9:
    bVar1 = *(short *)(unaff_r28 + 0xa0) != 0x18;
    if ((bVar1) || ((!bVar1 && (*(float *)(unaff_r28 + 0x98) < FLOAT_803e467c)))) {
      *(undefined *)(piVar10 + 4) = 10;
    }
    break;
  case 10:
    if ((*(short *)(unaff_r28 + 0xa0) != 0x18) || (*(float *)(unaff_r28 + 0x98) <= FLOAT_803e467c))
    {
      if (*(short *)(unaff_r28 + 0xa0) == 0x19) {
        *(undefined *)(piVar10 + 4) = 5;
      }
      else if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
        FUN_801aa878(in_f31,piVar10,unaff_r28);
      }
    }
    else {
      *(undefined *)(piVar10 + 4) = 8;
    }
    break;
  case 0xb:
    FUN_801aa878(in_f31,piVar10,unaff_r28);
    break;
  case 0xc:
    iVar7 = FUN_8001ffb4(9);
    if (iVar7 == 0) {
      iVar7 = FUN_80038024(psVar2);
      if (iVar7 == 0) {
        if ((*(byte *)((int)piVar10 + 0x11) & 2) != 0) {
          *(undefined *)(piVar10 + 4) = 0xd;
        }
      }
      else {
        FUN_800200e8(9,1);
      }
    }
    else {
      iVar7 = FUN_8001ffb4(0x24);
      if (iVar7 != 0) {
        *(undefined *)(piVar10 + 4) = 0xe;
      }
    }
    break;
  case 0xd:
    if ((FLOAT_803e467c < *(float *)(psVar2 + 0x4c)) && (*(float *)(psVar2 + 0x4c) < FLOAT_803e4688)
       ) {
      if (unaff_r26 < 0x401) {
        if (unaff_r26 < -0x400) {
          local_40 = (double)(longlong)(int)(FLOAT_803e468c * FLOAT_803db414);
          *psVar2 = *psVar2 + (short)(int)(FLOAT_803e468c * FLOAT_803db414);
        }
        else {
          *psVar2 = unaff_r27;
        }
      }
      else {
        local_40 = (double)(longlong)(int)(FLOAT_803e468c * FLOAT_803db414);
        *psVar2 = *psVar2 - (short)(int)(FLOAT_803e468c * FLOAT_803db414);
      }
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 0xc;
    }
    break;
  case 0xe:
    if (*piVar10 != 0) {
      if (*(int *)(psVar2 + 100) != 0) {
        FUN_80037cb0(psVar2);
      }
      FUN_8002cbc4(*piVar10);
      *piVar10 = 0;
    }
    psVar2[3] = psVar2[3] | 0x4000;
    psVar2[0x58] = psVar2[0x58] | 0x8000;
    FUN_80035f00(psVar2);
    goto LAB_801ab418;
  }
  if ((*(byte *)(piVar10 + 4) < 5) || (10 < *(byte *)(piVar10 + 4))) {
    iVar7 = FUN_8003687c(psVar2,&local_58,0,0);
    if ((iVar7 != 0) &&
       ((*(short *)(local_58 + 0x46) == 0x11 || (*(short *)(local_58 + 0x46) == 0x33)))) {
      FUN_8002ac30(psVar2,0xf,200,0,0,1);
    }
  }
  else {
    iVar7 = FUN_80037a68(psVar2,&DAT_803ddb38,0,auStack76);
    if (iVar7 != 0) {
      dVar12 = (double)FUN_8002166c(psVar2 + 0xc,piVar10[1] + 0x18);
      if (dVar12 < (double)FLOAT_803e4690) {
        FUN_80096f9c(auStack76,8,0xff,0xff,0x78);
        FUN_8009a1dc((double)FLOAT_803e4694,psVar2,auStack76,4,0);
      }
      FUN_8000bb18(psVar2,0x129);
    }
  }
  uVar4 = (uint)(byte)(&DAT_80323418)[*(byte *)(piVar10 + 4)];
  if (uVar4 != (int)psVar2[0x50]) {
    if (((&DAT_80323408)[*(byte *)(piVar10 + 4)] & 2) == 0) {
      FUN_80030334((double)FLOAT_803e4680,psVar2,uVar4,0);
    }
    else {
      FUN_80030334((double)FLOAT_803e4698,psVar2,uVar4,0);
    }
  }
  iVar7 = FUN_8002fa48((double)*(float *)(&DAT_80323428 + (uint)*(byte *)(piVar10 + 4) * 4),
                       (double)FLOAT_803db414,psVar2,0);
  if (iVar7 == 0) {
    *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) & 0xfe;
  }
  else {
    *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 1;
  }
LAB_801ab418:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_8028611c();
  return;
}

