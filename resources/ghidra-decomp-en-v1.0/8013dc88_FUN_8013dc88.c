// Function: FUN_8013dc88
// Entry: 8013dc88
// Size: 1096 bytes

/* WARNING: Removing unreachable block (ram,0x8013dcc8) */

void FUN_8013dc88(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  float *pfVar4;
  short sVar8;
  int iVar5;
  int iVar6;
  char cVar9;
  char *pcVar7;
  char **ppcVar10;
  char **ppcVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  ppcVar10 = (char **)uVar12;
  bVar1 = *(byte *)((int)ppcVar10 + 10);
  if (bVar1 == 2) {
    FUN_80148bc8(s_GROWLAT_GOTOFLAME_8031d864);
    iVar5 = FUN_8013b368((double)FLOAT_803e24cc,iVar3,ppcVar10);
    if (iVar5 == 0) {
      cVar9 = FUN_8002e04c();
      if (cVar9 != '\0') {
        ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] | 0x800);
        iVar5 = 0;
        ppcVar11 = ppcVar10;
        do {
          iVar6 = FUN_8002bdf4(0x24,0x4f0);
          *(undefined *)(iVar6 + 4) = 2;
          *(undefined *)(iVar6 + 5) = 1;
          *(short *)(iVar6 + 0x1a) = (short)iVar5;
          pcVar7 = (char *)FUN_8002df90(iVar6,5,(int)*(char *)(iVar3 + 0xac),0xffffffff,
                                        *(undefined4 *)(iVar3 + 0x30));
          ppcVar11[0x1c0] = pcVar7;
          ppcVar11 = ppcVar11 + 1;
          iVar5 = iVar5 + 1;
        } while (iVar5 < 7);
        FUN_8000bb18(iVar3,0x3db);
        FUN_8000dcbc(iVar3,0x3dc);
      }
      **ppcVar10 = **ppcVar10 + -1;
      FUN_8013a3f0((double)FLOAT_803e2444,iVar3,0x34,0x4000000);
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] | 0x10);
      *(undefined *)((int)ppcVar10 + 10) = 3;
      ppcVar10[0x1ca] = (char *)0x0;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      FUN_80148bc8(s_GROWLAT_GOTO_8031d840);
      iVar5 = FUN_8013b368((double)FLOAT_803e24c8,iVar3,ppcVar10);
      if (iVar5 == 0) {
        iVar5 = *(int *)(iVar3 + 0xb8);
        if ((((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
            ((0x2f < *(short *)(iVar3 + 0xa0) || (*(short *)(iVar3 + 0xa0) < 0x29)))) &&
           (iVar6 = FUN_8000b578(iVar3,0x10), iVar6 == 0)) {
          FUN_800393f8(iVar3,iVar5 + 0x3a8,0x299,0x100,0xffffffff,0);
        }
        *(undefined *)((int)ppcVar10 + 10) = 1;
        FUN_8013a3f0((double)FLOAT_803e2444,iVar3,0x33,0x4000000);
        ppcVar10[0x1ca] = (char *)0x0;
      }
    }
    else {
      FUN_80148bc8(s_GROWLAT_GROWLING_8031d850);
      if ((**ppcVar10 == '\0') || (ppcVar10[0x1ca] == (char *)0x0)) {
        pfVar4 = *(float **)(*(int *)(iVar3 + 0xb8) + 0x28);
        sVar8 = FUN_800217c0(-(double)(*pfVar4 - *(float *)(iVar3 + 0x18)),
                             -(double)(pfVar4[2] - *(float *)(iVar3 + 0x20)));
        FUN_80139930(iVar3,(int)sVar8);
        iVar5 = FUN_800221a0(0,10);
        if (((iVar5 == 0) &&
            (iVar5 = *(int *)(iVar3 + 0xb8), (*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0)) &&
           (((0x2f < *(short *)(iVar3 + 0xa0) || (*(short *)(iVar3 + 0xa0) < 0x29)) &&
            (iVar6 = FUN_8000b578(iVar3,0x10), iVar6 == 0)))) {
          FUN_800393f8(iVar3,iVar5 + 0x3a8,0x299,0x100,0xffffffff,0);
        }
      }
      else {
        *(undefined *)((int)ppcVar10 + 10) = 2;
      }
    }
  }
  else if (bVar1 < 4) {
    FUN_80148bc8(s_GROWLAT_FLAME_8031d878);
    if (*(float *)(iVar3 + 0x98) < FLOAT_803e24d0) {
      pfVar4 = *(float **)(*(int *)(iVar3 + 0xb8) + 0x28);
      sVar8 = FUN_800217c0(-(double)(*pfVar4 - *(float *)(iVar3 + 0x18)),
                           -(double)(pfVar4[2] - *(float *)(iVar3 + 0x20)));
      FUN_80139930(iVar3,(int)sVar8);
    }
    else {
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] & 0xfffff7ff);
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] | 0x1000);
      iVar5 = 0;
      ppcVar11 = ppcVar10;
      do {
        FUN_8017804c(ppcVar11[0x1c0]);
        ppcVar11 = ppcVar11 + 1;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 7);
      FUN_8000db90(iVar3,0x3dc);
      iVar5 = *(int *)(iVar3 + 0xb8);
      if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar3 + 0xa0) || (*(short *)(iVar3 + 0xa0) < 0x29)) &&
          (iVar6 = FUN_8000b578(iVar3,0x10), iVar6 == 0)))) {
        FUN_800393f8(iVar3,iVar5 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      *(undefined *)(ppcVar10 + 2) = 1;
      *(undefined *)((int)ppcVar10 + 10) = 0;
      fVar2 = FLOAT_803e23dc;
      ppcVar10[0x1c7] = (char *)FLOAT_803e23dc;
      ppcVar10[0x1c8] = (char *)fVar2;
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] & 0xffffffef);
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] & 0xfffeffff);
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] & 0xfffdffff);
      ppcVar10[0x15] = (char *)((uint)ppcVar10[0x15] & 0xfffbffff);
      *(undefined *)((int)ppcVar10 + 0xd) = 0xff;
    }
  }
  FUN_80286124();
  return;
}

