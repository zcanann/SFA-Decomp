// Function: FUN_801f166c
// Entry: 801f166c
// Size: 1104 bytes

/* WARNING: Removing unreachable block (ram,0x801f1a9c) */

void FUN_801f166c(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  int iVar9;
  bool bVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = FUN_802860d8();
  iVar4 = FUN_8002b9ec();
  iVar9 = *(int *)(iVar3 + 0x4c);
  pcVar8 = *(char **)(iVar3 + 0xb8);
  dVar13 = (double)FUN_80021704(iVar3 + 0x18,iVar4 + 0x18);
  dVar12 = (double)FLOAT_803e5d5c;
  *pcVar8 = *pcVar8 + -1;
  if (*pcVar8 < '\0') {
    *pcVar8 = '\0';
    pcVar8[1] = '\0';
  }
  iVar4 = 0;
  pcVar8[6] = pcVar8[6] & 0x7f;
  if ((*(int *)(iVar3 + 0x58) == 0) || (*(char *)(*(int *)(iVar3 + 0x58) + 0x10f) < '\x01')) {
    if ((*(char *)(iVar3 + 0xac) == '\v') &&
       (((cVar5 = (**(code **)(*DAT_803dcaac + 0x40))(), cVar5 == '\x03' &&
         (iVar4 = FUN_8002b9ac(), iVar4 != 0)) &&
        (dVar14 = (double)FUN_80021704(iVar3 + 0x18,iVar4 + 0x18), dVar14 < (double)FLOAT_803e5d64))
       )) {
      *pcVar8 = '\x05';
    }
  }
  else {
    *(short *)(pcVar8 + 2) = *(short *)(iVar9 + 0x1e) * 0x3c;
    dVar14 = (double)FLOAT_803e5d60;
    for (iVar7 = 0; iVar7 < *(char *)(*(int *)(iVar3 + 0x58) + 0x10f); iVar7 = iVar7 + 1) {
      iVar6 = *(int *)(*(int *)(iVar3 + 0x58) + iVar4 + 0x100);
      if (*(short *)(iVar6 + 0x46) == 0x6d) {
        pcVar8[6] = pcVar8[6] & 0x7fU | 0x80;
      }
      if (dVar14 < (double)(*(float *)(iVar6 + 0x10) - *(float *)(iVar3 + 0x10))) {
        *pcVar8 = '\x05';
      }
      if (((pcVar8[1] == '\0') && (iVar6 != 0)) && (*(short *)(iVar6 + 0x46) == 0x146)) {
        if (dVar13 <= dVar12) {
          FUN_8000bb18(iVar3,0x7e);
        }
        pcVar8[1] = '\x01';
      }
      iVar4 = iVar4 + 4;
    }
  }
  if (((*(char *)(iVar3 + 0xac) == '\v') &&
      (cVar5 = (**(code **)(*DAT_803dcaac + 0x40))(), cVar5 == '\x01')) && (dVar13 <= dVar12)) {
    if (*pcVar8 == '\0') {
      iVar4 = FUN_8001ffb4(0x905);
      if (iVar4 != 0) {
        FUN_800200e8(0x905,0);
      }
    }
    else {
      fVar1 = *(float *)(iVar9 + 0xc) - *(float *)(iVar3 + 0x10);
      if (((fVar1 <= FLOAT_803e5d68) || (FLOAT_803e5d6c <= fVar1)) ||
         (iVar4 = FUN_8001ffb4((int)*(short *)(pcVar8 + 4)), iVar4 != 0)) {
        iVar4 = FUN_8001ffb4(0x905);
        if (iVar4 != 0) {
          FUN_800200e8(0x905,0);
        }
      }
      else {
        FUN_800200e8(0x905,1);
      }
    }
  }
  bVar10 = false;
  if (*pcVar8 == '\0') {
    if (*(short *)(pcVar8 + 2) == 0) {
      *(float *)(iVar3 + 0x10) = FLOAT_803e5d74 * FLOAT_803db414 + *(float *)(iVar3 + 0x10);
      bVar10 = *(float *)(iVar3 + 0x10) <= *(float *)(iVar9 + 0xc);
      if (!bVar10) {
        *(float *)(iVar3 + 0x10) = *(float *)(iVar9 + 0xc);
      }
      FUN_800200e8((int)*(short *)(iVar9 + 0x1c),0);
      if ((*(short *)(pcVar8 + 4) != -1) && (((byte)pcVar8[6] >> 6 & 1) == 0)) {
        FUN_800200e8((int)*(short *)(pcVar8 + 4),0);
      }
    }
  }
  else {
    fVar2 = *(float *)(iVar9 + 0xc) - FLOAT_803e5d6c;
    fVar1 = *(float *)(iVar3 + 0x10);
    if (fVar2 <= fVar1) {
      *(float *)(iVar3 + 0x10) = -(FLOAT_803e5d74 * FLOAT_803db414 - fVar1);
      if (fVar2 <= *(float *)(iVar3 + 0x10)) {
        bVar10 = true;
      }
      else {
        *(float *)(iVar3 + 0x10) = fVar2;
        FUN_800200e8((int)*(short *)(iVar9 + 0x1c),1);
        if (*(short *)(pcVar8 + 4) != -1) {
          FUN_800200e8((int)*(short *)(pcVar8 + 4),1);
          if (pcVar8[6] < '\0') {
            pcVar8[6] = pcVar8[6] & 0xbfU | 0x40;
          }
        }
      }
    }
    else {
      *(float *)(iVar3 + 0x10) = FLOAT_803e5d70 * FLOAT_803db414 + fVar1;
      if (fVar2 < *(float *)(iVar3 + 0x10)) {
        *(float *)(iVar3 + 0x10) = fVar2;
      }
      FUN_800200e8((int)*(short *)(iVar9 + 0x1c),1);
      if (pcVar8[6] < '\0') {
        FUN_800200e8((int)*(short *)(pcVar8 + 4),1);
      }
    }
  }
  if (bVar10) {
    FUN_8000bb18(iVar3,0x7f);
  }
  else {
    FUN_8000b7bc(iVar3,8);
  }
  if ((*(short *)(pcVar8 + 2) != 0) &&
     (*(ushort *)(pcVar8 + 2) = *(short *)(pcVar8 + 2) - (ushort)DAT_803db410,
     *(short *)(pcVar8 + 2) < 0)) {
    *(undefined2 *)(pcVar8 + 2) = 0;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286124();
  return;
}

