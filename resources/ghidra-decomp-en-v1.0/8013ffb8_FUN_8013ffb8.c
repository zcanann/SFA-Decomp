// Function: FUN_8013ffb8
// Entry: 8013ffb8
// Size: 2276 bytes

void FUN_8013ffb8(void)

{
  bool bVar1;
  char cVar9;
  char **ppcVar2;
  int iVar3;
  int iVar4;
  char **ppcVar5;
  float *pfVar6;
  short sVar8;
  int iVar7;
  char *pcVar10;
  double dVar11;
  undefined8 uVar12;
  int local_48;
  int local_44;
  int local_40 [2];
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  
  uVar12 = FUN_802860d4();
  iVar7 = (int)((ulonglong)uVar12 >> 0x20);
  ppcVar2 = (char **)uVar12;
  switch(*(undefined *)((int)ppcVar2 + 10)) {
  case 0:
    FUN_80148bc8(s_GUARD_INIT_8031d930);
    pcVar10 = (char *)FUN_800dbcfc(ppcVar2[10],0);
    ppcVar2[0x1cc] = pcVar10;
    uStack52 = (int)*(short *)ppcVar2[9] ^ 0x80000000;
    local_38 = 0x43300000;
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e2454 *
                                           (float)((double)CONCAT44(0x43300000,uStack52) -
                                                  DOUBLE_803e2460)) / FLOAT_803e2458));
    ppcVar2[0x1c7] =
         (char *)-(float)((double)FLOAT_803e247c * dVar11 - (double)*(float *)(ppcVar2[9] + 0x18));
    ppcVar2[0x1c8] = *(char **)(ppcVar2[9] + 0x1c);
    uStack44 = (int)*(short *)ppcVar2[9] ^ 0x80000000;
    local_30 = 0x43300000;
    dVar11 = (double)FUN_80294204((double)((FLOAT_803e2454 *
                                           (float)((double)CONCAT44(0x43300000,uStack44) -
                                                  DOUBLE_803e2460)) / FLOAT_803e2458));
    ppcVar2[0x1c9] =
         (char *)-(float)((double)FLOAT_803e247c * dVar11 - (double)*(float *)(ppcVar2[9] + 0x20));
    *(undefined *)(ppcVar2 + 0x1cd) = 0;
    *(undefined *)((int)ppcVar2 + 10) = 1;
    break;
  case 1:
    FUN_80148bc8(s_GUARD_FINDING_8031d93c);
    FUN_8013b368((double)FLOAT_803e2488,iVar7,ppcVar2);
    pcVar10 = (char *)FUN_800dbcfc(iVar7 + 0x18,0);
    if (ppcVar2[0x1cc] == pcVar10) {
      *(undefined *)((int)ppcVar2 + 10) = 2;
    }
    break;
  case 2:
    FUN_80148bc8(s_GUARD_TOSPOT_8031d94c);
    iVar3 = FUN_8013b368((double)FLOAT_803e2488,iVar7,ppcVar2);
    if (iVar3 != 0) {
      FUN_8014089c(ppcVar2);
      break;
    }
    if ((char **)ppcVar2[10] != ppcVar2 + 0x1c7) {
      ppcVar2[10] = (char *)(ppcVar2 + 0x1c7);
      ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xfffffbff);
      *(undefined2 *)((int)ppcVar2 + 0xd2) = 0;
    }
    *(undefined *)((int)ppcVar2 + 10) = 3;
  case 3:
    FUN_80148bc8(s_GUARD_TOFRONT_8031d95c);
    iVar3 = FUN_8013b368((double)FLOAT_803e2488,iVar7,ppcVar2);
    if (iVar3 == 0) {
      if (FLOAT_803e23dc == (float)ppcVar2[0xab]) {
        bVar1 = false;
      }
      else if (FLOAT_803e2410 == (float)ppcVar2[0xac]) {
        bVar1 = true;
      }
      else if ((float)ppcVar2[0xad] - (float)ppcVar2[0xac] <= FLOAT_803e2414) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
      if (bVar1) {
        FUN_8013a3f0((double)FLOAT_803e243c,iVar7,8,0);
        ppcVar2[0x1e7] = (char *)FLOAT_803e2440;
        ppcVar2[0x20e] = (char *)FLOAT_803e23dc;
        FUN_80148bc8(s_in_water_8031d46c);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2444,iVar7,0,0);
        FUN_80148bc8(s_out_of_water_8031d478);
      }
    }
    FUN_8014089c(ppcVar2);
    break;
  case 4:
    FUN_80148bc8(s_GUARD_TOBADDIE_8031d96c);
    iVar3 = FUN_8013b368((double)FLOAT_803e247c,iVar7,ppcVar2);
    if (iVar3 != 0) {
      pcVar10 = (char *)FUN_800dbcfc(ppcVar2[10],0);
      if (ppcVar2[0x1cc] != pcVar10) {
        if (ppcVar2[10] != ppcVar2[9] + 0x18) {
          ppcVar2[10] = ppcVar2[9] + 0x18;
          ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppcVar2 + 0xd2) = 0;
        }
        *(undefined *)((int)ppcVar2 + 10) = 2;
      }
      break;
    }
    ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] | 0x10);
    if ((**ppcVar2 == '\0') || (*(char *)(ppcVar2 + 0x1cd) == '\0')) {
      FUN_8013a3f0((double)FLOAT_803e23ec,iVar7,0x32,0x4000000);
      *(undefined *)((int)ppcVar2 + 10) = 6;
    }
    else {
      cVar9 = FUN_8002e04c();
      if (cVar9 != '\0') {
        ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] | 0x800);
        iVar3 = 0;
        ppcVar5 = ppcVar2;
        do {
          iVar4 = FUN_8002bdf4(0x24,0x4f0);
          *(undefined *)(iVar4 + 4) = 2;
          *(undefined *)(iVar4 + 5) = 1;
          *(short *)(iVar4 + 0x1a) = (short)iVar3;
          pcVar10 = (char *)FUN_8002df90(iVar4,5,(int)*(char *)(iVar7 + 0xac),0xffffffff,
                                         *(undefined4 *)(iVar7 + 0x30));
          ppcVar5[0x1c0] = pcVar10;
          ppcVar5 = ppcVar5 + 1;
          iVar3 = iVar3 + 1;
        } while (iVar3 < 7);
        FUN_8000bb18(iVar7,0x3db);
        FUN_8000dcbc(iVar7,0x3dc);
      }
      **ppcVar2 = **ppcVar2 + -1;
      FUN_8013a3f0((double)FLOAT_803e2444,iVar7,0x34,0x4000000);
      *(undefined *)((int)ppcVar2 + 10) = 5;
    }
  case 5:
    FUN_80148bc8(s_GUARD_FLAME_8031d97c);
    if (*(float *)(iVar7 + 0x98) < FLOAT_803e24d0) {
      pcVar10 = ppcVar2[0x1cb];
      ppcVar2 = (char **)FUN_80036f50(3,local_40);
      for (sVar8 = 0; sVar8 < local_40[0]; sVar8 = sVar8 + 1) {
        if (*ppcVar2 == pcVar10) {
          bVar1 = true;
          goto LAB_80140538;
        }
        ppcVar2 = ppcVar2 + 1;
      }
      bVar1 = false;
LAB_80140538:
      if (bVar1) {
        pfVar6 = *(float **)(*(int *)(iVar7 + 0xb8) + 0x28);
        sVar8 = FUN_800217c0(-(double)(*pfVar6 - *(float *)(iVar7 + 0x18)),
                             -(double)(pfVar6[2] - *(float *)(iVar7 + 0x20)));
        FUN_80139930(iVar7,(int)sVar8);
      }
    }
    else {
      ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xfffff7ff);
      ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] | 0x1000);
      iVar3 = 0;
      ppcVar5 = ppcVar2;
      do {
        FUN_8017804c(ppcVar5[0x1c0]);
        ppcVar5 = ppcVar5 + 1;
        iVar3 = iVar3 + 1;
      } while (iVar3 < 7);
      FUN_8000db90(iVar7,0x3dc);
      iVar3 = *(int *)(iVar7 + 0xb8);
      if ((((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(iVar7 + 0xa0) || (*(short *)(iVar7 + 0xa0) < 0x29)))) &&
         (iVar4 = FUN_8000b578(iVar7,0x10), iVar4 == 0)) {
        FUN_800393f8(iVar7,iVar3 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xffffffef);
      iVar7 = FUN_8014089c(ppcVar2);
      if (iVar7 == 0) {
        if (ppcVar2[10] != ppcVar2[9] + 0x18) {
          ppcVar2[10] = ppcVar2[9] + 0x18;
          ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppcVar2 + 0xd2) = 0;
        }
        *(undefined *)((int)ppcVar2 + 10) = 2;
      }
    }
    break;
  case 6:
    FUN_80148bc8(s_GUARD_DOWNTOGROWL_8031d98c);
    if (*(float *)(iVar7 + 0x98) < FLOAT_803e24d0) {
      pcVar10 = ppcVar2[0x1cb];
      ppcVar2 = (char **)FUN_80036f50(3,&local_44);
      for (sVar8 = 0; sVar8 < local_44; sVar8 = sVar8 + 1) {
        if (*ppcVar2 == pcVar10) {
          bVar1 = true;
          goto LAB_80140664;
        }
        ppcVar2 = ppcVar2 + 1;
      }
      bVar1 = false;
LAB_80140664:
      if (bVar1) {
        pfVar6 = *(float **)(*(int *)(iVar7 + 0xb8) + 0x28);
        sVar8 = FUN_800217c0(-(double)(*pfVar6 - *(float *)(iVar7 + 0x18)),
                             -(double)(pfVar6[2] - *(float *)(iVar7 + 0x20)));
        FUN_80139930(iVar7,(int)sVar8);
      }
    }
    else {
      FUN_8013a3f0((double)FLOAT_803e2444,iVar7,0x33,0x4000000);
      ppcVar2[0x1ca] = (char *)FLOAT_803e23dc;
      iVar3 = *(int *)(iVar7 + 0xb8);
      if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar7 + 0xa0) || (*(short *)(iVar7 + 0xa0) < 0x29)) &&
          (iVar4 = FUN_8000b578(iVar7,0x10), iVar4 == 0)))) {
        FUN_800393f8(iVar7,iVar3 + 0x3a8,0x299,0x100,0xffffffff,0);
      }
      *(undefined *)((int)ppcVar2 + 10) = 7;
    }
    break;
  case 7:
    FUN_80148bc8(s_GUARD_GROWL_8031d9a0);
    iVar3 = FUN_800221a0(0,10);
    if ((((iVar3 == 0) && (iVar3 = *(int *)(iVar7 + 0xb8), (*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0))
        && ((0x2f < *(short *)(iVar7 + 0xa0) || (*(short *)(iVar7 + 0xa0) < 0x29)))) &&
       (iVar4 = FUN_8000b578(iVar7,0x10), iVar4 == 0)) {
      FUN_800393f8(iVar7,iVar3 + 0x3a8,0x299,0x100,0xffffffff,0);
    }
    ppcVar2[0x1ca] = (char *)((float)ppcVar2[0x1ca] + FLOAT_803db414);
    if (((float)ppcVar2[0x1ca] < FLOAT_803e24d8) ||
       (dVar11 = (double)FUN_8002166c(ppcVar2[10],iVar7 + 0x18), dVar11 < (double)FLOAT_803e24c4)) {
      pcVar10 = ppcVar2[0x1cb];
      ppcVar5 = (char **)FUN_80036f50(3,&local_48);
      for (sVar8 = 0; sVar8 < local_48; sVar8 = sVar8 + 1) {
        if (*ppcVar5 == pcVar10) {
          bVar1 = true;
          goto LAB_801407a8;
        }
        ppcVar5 = ppcVar5 + 1;
      }
      bVar1 = false;
LAB_801407a8:
      if (bVar1) {
        pfVar6 = *(float **)(*(int *)(iVar7 + 0xb8) + 0x28);
        sVar8 = FUN_800217c0(-(double)(*pfVar6 - *(float *)(iVar7 + 0x18)),
                             -(double)(pfVar6[2] - *(float *)(iVar7 + 0x20)));
        FUN_80139930(iVar7,(int)sVar8);
        break;
      }
    }
    FUN_8013a3f0((double)FLOAT_803e23f4,iVar7,0x32,0x4000000);
    *(undefined *)((int)ppcVar2 + 10) = 8;
    break;
  case 8:
    FUN_80148bc8(s_GUARD_UPFROMGROWL_8031d9b0);
    if (*(float *)(iVar7 + 0x98) <= FLOAT_803e2420) {
      ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xffffffef);
      iVar7 = FUN_8014089c(ppcVar2);
      if (iVar7 == 0) {
        if (ppcVar2[10] != ppcVar2[9] + 0x18) {
          ppcVar2[10] = ppcVar2[9] + 0x18;
          ppcVar2[0x15] = (char *)((uint)ppcVar2[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppcVar2 + 0xd2) = 0;
        }
        *(undefined *)((int)ppcVar2 + 10) = 2;
      }
    }
  }
  FUN_80286120();
  return;
}

