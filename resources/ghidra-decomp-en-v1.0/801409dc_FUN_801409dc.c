// Function: FUN_801409dc
// Entry: 801409dc
// Size: 2224 bytes

void FUN_801409dc(void)

{
  bool bVar1;
  float fVar2;
  short sVar3;
  short sVar4;
  short *psVar5;
  uint uVar6;
  char cVar10;
  int iVar7;
  char *pcVar8;
  int iVar9;
  char **ppcVar11;
  char **ppcVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860d8();
  psVar5 = (short *)((ulonglong)uVar13 >> 0x20);
  ppcVar11 = (char **)uVar13;
  switch(*(undefined *)((int)ppcVar11 + 10)) {
  case 0:
    FUN_80148bc8(s_FLAME_NONE_8031d9e8);
    pcVar8 = (char *)FUN_800dafdc(ppcVar11[9] + 0x18,0xffffffff,4);
    ppcVar11[0x1c7] = pcVar8;
    pcVar8 = ppcVar11[0x1c7];
    if (pcVar8[3] == '\0') {
      pcVar8 = (char *)(**(code **)(*DAT_803dca9c + 0x1c))(*(undefined4 *)(pcVar8 + 0x1c));
      ppcVar11[0x1c8] = pcVar8;
      if (ppcVar11[10] != ppcVar11[0x1c8] + 8) {
        ppcVar11[10] = ppcVar11[0x1c8] + 8;
        ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffffbff);
        *(undefined2 *)((int)ppcVar11 + 0xd2) = 0;
      }
      *(undefined *)((int)ppcVar11 + 10) = 3;
    }
    else {
      if (ppcVar11[10] != pcVar8 + 8) {
        ppcVar11[10] = pcVar8 + 8;
        ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffffbff);
        *(undefined2 *)((int)ppcVar11 + 0xd2) = 0;
      }
      *(undefined *)((int)ppcVar11 + 10) = 1;
    }
    FUN_8013b368((double)FLOAT_803e2488,psVar5,ppcVar11);
    break;
  case 1:
    FUN_80148bc8(s_FLAME_FINDING_IN_8031da38);
    iVar9 = FUN_8013b368((double)FLOAT_803e2488,psVar5,ppcVar11);
    if (iVar9 == 0) {
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] | 0x10);
      *(undefined *)((int)ppcVar11 + 10) = 2;
    }
    else if (iVar9 == 2) {
      *(undefined *)(ppcVar11 + 2) = 1;
      *(undefined *)((int)ppcVar11 + 10) = 0;
      fVar2 = FLOAT_803e23dc;
      ppcVar11[0x1c7] = (char *)FLOAT_803e23dc;
      ppcVar11[0x1c8] = (char *)fVar2;
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xffffffef);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffeffff);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffdffff);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffbffff);
      *(undefined *)((int)ppcVar11 + 0xd) = 0xff;
    }
    break;
  case 2:
    FUN_80148bc8(s_FLAME_TURNING_IN_8031da4c);
    pcVar8 = ppcVar11[9];
    FUN_8013d5a4((double)FLOAT_803e2418,psVar5,ppcVar11,pcVar8 + 0x18,1);
    iVar9 = FUN_80139a8c(psVar5,pcVar8 + 0x18);
    if (iVar9 == 0) {
      FUN_8013a3f0((double)FLOAT_803e23e4,psVar5,0x1a,0x4000000);
      *(undefined *)((int)ppcVar11 + 10) = 6;
      **ppcVar11 = **ppcVar11 + -4;
    }
    break;
  case 3:
    FUN_80148bc8(s_FLAME_FINDING_OUT_8031d9f4);
    FUN_8013b368((double)FLOAT_803e2488,psVar5,ppcVar11);
    uVar6 = FUN_800dbcfc(psVar5 + 0xc,0);
    if ((byte)ppcVar11[0x1c8][3] == uVar6) {
      *(undefined *)((int)ppcVar11 + 9) = 1;
      *(undefined *)((int)ppcVar11 + 10) = 4;
    }
    break;
  case 4:
    FUN_80148bc8(s_FLAME_GOINGTOEDGE_8031da08);
    pcVar8 = ppcVar11[0x1c7];
    FUN_8013d5a4((double)FLOAT_803e2488,psVar5,ppcVar11,pcVar8 + 8,1);
    FUN_80139a8c(psVar5,pcVar8 + 8);
    iVar9 = FUN_800dbcfc(psVar5 + 0xc,0);
    if (iVar9 == 0) {
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] | 0x10);
      *(undefined *)((int)ppcVar11 + 10) = 5;
    }
    break;
  case 5:
    FUN_80148bc8(s_FLAME_TOSTART_8031da1c);
    pcVar8 = ppcVar11[0x1c7];
    FUN_8013d5a4((double)FLOAT_803e2488,psVar5,ppcVar11,pcVar8 + 8,1);
    iVar9 = FUN_80139a8c(psVar5,pcVar8 + 8);
    if (iVar9 != 0) break;
    FUN_8013a3f0((double)FLOAT_803e23e4,psVar5,0x1a,0x4000000);
    *(undefined *)((int)ppcVar11 + 10) = 7;
    **ppcVar11 = **ppcVar11 + -4;
  case 7:
    FUN_80148bc8(s_FLAME_OUT_8031da2c);
    sVar4 = (short)((int)ppcVar11[0x1c7][0x2c] << 8);
    sVar3 = sVar4 - *psVar5;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar9 = (int)sVar3;
    if (iVar9 < 0) {
      iVar9 = -iVar9;
    }
    if (0x3fff < iVar9) {
      sVar4 = sVar4 + -0x8000;
    }
    FUN_80139930(psVar5,(int)sVar4);
    if (*(float *)(psVar5 + 0x4c) <= FLOAT_803e24ac) {
LAB_80140e34:
      bVar1 = true;
    }
    else {
      if (((uint)ppcVar11[0x15] & 0x800) == 0) {
        cVar10 = FUN_8002e04c();
        if (cVar10 != '\0') {
          ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] | 0x800);
          iVar9 = 0;
          ppcVar12 = ppcVar11;
          do {
            iVar7 = FUN_8002bdf4(0x24,0x4f0);
            *(undefined *)(iVar7 + 4) = 2;
            *(undefined *)(iVar7 + 5) = 1;
            *(short *)(iVar7 + 0x1a) = (short)iVar9;
            pcVar8 = (char *)FUN_8002df90(iVar7,5,(int)*(char *)(psVar5 + 0x56),0xffffffff,
                                          *(undefined4 *)(psVar5 + 0x18));
            ppcVar12[0x1c0] = pcVar8;
            ppcVar12 = ppcVar12 + 1;
            iVar9 = iVar9 + 1;
          } while (iVar9 < 7);
          FUN_8000bb18(psVar5,0x3db);
          FUN_8000dcbc(psVar5,0x3dc);
        }
        goto LAB_80140e34;
      }
      if ((((code *)ppcVar11[0x1c9] != (code *)0x0) &&
          (iVar9 = (*(code *)ppcVar11[0x1c9])(ppcVar11[9],1), iVar9 == 0)) ||
         (*(float *)(psVar5 + 0x4c) <= FLOAT_803e2504)) goto LAB_80140e34;
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffff7ff);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] | 0x1000);
      iVar9 = 0;
      ppcVar12 = ppcVar11;
      do {
        FUN_8017804c(ppcVar12[0x1c0]);
        ppcVar12 = ppcVar12 + 1;
        iVar9 = iVar9 + 1;
      } while (iVar9 < 7);
      FUN_8000db90(psVar5,0x3dc);
      iVar9 = *(int *)(psVar5 + 0x5c);
      if (((*(byte *)(iVar9 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < psVar5[0x50] || (psVar5[0x50] < 0x29)) &&
          (iVar7 = FUN_8000b578(psVar5,0x10), iVar7 == 0)))) {
        FUN_800393f8(psVar5,iVar9 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      bVar1 = false;
    }
    if (!bVar1) {
      *(undefined *)((int)ppcVar11 + 10) = 8;
      ppcVar11[0x1ca] = (char *)FLOAT_803e24f8;
    }
    break;
  case 6:
    FUN_80148bc8(s_FLAME_IN_8031da60);
    if (*(float *)(psVar5 + 0x4c) <= FLOAT_803e24ac) {
LAB_80141114:
      bVar1 = true;
    }
    else {
      if (((uint)ppcVar11[0x15] & 0x800) == 0) {
        cVar10 = FUN_8002e04c();
        if (cVar10 != '\0') {
          ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] | 0x800);
          iVar9 = 0;
          ppcVar12 = ppcVar11;
          do {
            iVar7 = FUN_8002bdf4(0x24,0x4f0);
            *(undefined *)(iVar7 + 4) = 2;
            *(undefined *)(iVar7 + 5) = 1;
            *(short *)(iVar7 + 0x1a) = (short)iVar9;
            pcVar8 = (char *)FUN_8002df90(iVar7,5,(int)*(char *)(psVar5 + 0x56),0xffffffff,
                                          *(undefined4 *)(psVar5 + 0x18));
            ppcVar12[0x1c0] = pcVar8;
            ppcVar12 = ppcVar12 + 1;
            iVar9 = iVar9 + 1;
          } while (iVar9 < 7);
          FUN_8000bb18(psVar5,0x3db);
          FUN_8000dcbc(psVar5,0x3dc);
        }
        goto LAB_80141114;
      }
      if ((((code *)ppcVar11[0x1c9] != (code *)0x0) &&
          (iVar9 = (*(code *)ppcVar11[0x1c9])(ppcVar11[9],1), iVar9 == 0)) ||
         (*(float *)(psVar5 + 0x4c) <= FLOAT_803e2504)) goto LAB_80141114;
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffff7ff);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] | 0x1000);
      iVar9 = 0;
      ppcVar12 = ppcVar11;
      do {
        FUN_8017804c(ppcVar12[0x1c0]);
        ppcVar12 = ppcVar12 + 1;
        iVar9 = iVar9 + 1;
      } while (iVar9 < 7);
      FUN_8000db90(psVar5,0x3dc);
      iVar9 = *(int *)(psVar5 + 0x5c);
      if ((((*(byte *)(iVar9 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < psVar5[0x50] || (psVar5[0x50] < 0x29)))) &&
         (iVar7 = FUN_8000b578(psVar5,0x10), iVar7 == 0)) {
        FUN_800393f8(psVar5,iVar9 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      bVar1 = false;
    }
    if (!bVar1) {
      *(undefined *)(ppcVar11 + 2) = 1;
      *(undefined *)((int)ppcVar11 + 10) = 0;
      fVar2 = FLOAT_803e23dc;
      ppcVar11[0x1c7] = (char *)FLOAT_803e23dc;
      ppcVar11[0x1c8] = (char *)fVar2;
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xffffffef);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffeffff);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffdffff);
      ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffbffff);
      *(undefined *)((int)ppcVar11 + 0xd) = 0xff;
    }
    break;
  case 8:
    FUN_80148bc8(s_FLAME_TOEND_8031da6c);
    ppcVar11[0x1ca] = (char *)((float)ppcVar11[0x1ca] - FLOAT_803db414);
    if ((float)ppcVar11[0x1ca] <= FLOAT_803e23dc) {
      pcVar8 = ppcVar11[0x1c8];
      FUN_8013d5a4((double)FLOAT_803e2488,psVar5,ppcVar11,pcVar8 + 8,1);
      FUN_80139a8c(psVar5,pcVar8 + 8);
      iVar9 = FUN_800dbcfc(psVar5 + 0xc,0);
      if (iVar9 != 0) {
        *(undefined *)(ppcVar11 + 2) = 1;
        *(undefined *)((int)ppcVar11 + 10) = 0;
        fVar2 = FLOAT_803e23dc;
        ppcVar11[0x1c7] = (char *)FLOAT_803e23dc;
        ppcVar11[0x1c8] = (char *)fVar2;
        ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xffffffef);
        ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffeffff);
        ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffdffff);
        ppcVar11[0x15] = (char *)((uint)ppcVar11[0x15] & 0xfffbffff);
        *(undefined *)((int)ppcVar11 + 0xd) = 0xff;
      }
    }
  }
  FUN_80286124();
  return;
}

