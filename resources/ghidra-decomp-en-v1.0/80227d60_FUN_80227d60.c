// Function: FUN_80227d60
// Entry: 80227d60
// Size: 840 bytes

/* WARNING: Removing unreachable block (ram,0x80228084) */

void FUN_80227d60(int param_1)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  uint uVar6;
  bool bVar7;
  byte bVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  char *pcVar12;
  int iVar13;
  undefined4 uVar14;
  undefined8 in_f31;
  double dVar15;
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar13 = *(int *)(param_1 + 0x4c);
  pcVar12 = *(char **)(param_1 + 0xb8);
  if ((*(short *)(iVar13 + 0x20) < 1) || (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
    cVar1 = *pcVar12;
    *pcVar12 = cVar1 + -1;
    if ((char)(cVar1 + -1) < '\0') {
      *pcVar12 = '\0';
    }
    dVar15 = DOUBLE_803e6e08;
    if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
      iVar3 = 0;
      for (iVar11 = 0; iVar11 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar11 = iVar11 + 1) {
        iVar10 = *(int *)(*(int *)(param_1 + 0x58) + iVar3 + 0x100);
        if ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1d)) - dVar15) <
            *(float *)(iVar10 + 0x10) - *(float *)(param_1 + 0x10)) {
          iVar9 = *(int *)(param_1 + 0xb8);
          uVar6 = 0;
          while( true ) {
            uVar2 = uVar6 & 0xff;
            iVar4 = uVar2 * 4 + 4;
            if ((*(int *)(iVar9 + iVar4) == 0) && (uVar2 != 9)) break;
            uVar6 = uVar6 + 1;
          }
          *(int *)(iVar9 + iVar4) = iVar10;
          iVar9 = iVar9 + uVar2 * 8;
          *(undefined4 *)(iVar9 + 0x2c) = *(undefined4 *)(iVar10 + 0xc);
          *(undefined4 *)(iVar9 + 0x30) = *(undefined4 *)(iVar10 + 0x14);
        }
        iVar3 = iVar3 + 4;
      }
    }
    iVar3 = *(int *)(param_1 + 0xb8);
    bVar7 = false;
    for (bVar8 = 0; bVar8 < 10; bVar8 = bVar8 + 1) {
      iVar10 = (uint)bVar8 * 4 + 4;
      iVar11 = *(int *)(iVar3 + iVar10);
      if (iVar11 != 0) {
        iVar9 = iVar3 + (uint)bVar8 * 8;
        if ((*(float *)(iVar9 + 0x2c) == *(float *)(iVar11 + 0xc)) &&
           (*(float *)(iVar9 + 0x30) == *(float *)(iVar11 + 0x14))) {
          bVar7 = true;
        }
        else {
          *(undefined4 *)(iVar3 + iVar10) = 0;
        }
      }
    }
    if (bVar7) {
      *pcVar12 = '\x05';
    }
    dVar15 = (double)(*(float *)(iVar13 + 0xc) -
                     (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1c)) -
                            DOUBLE_803e6e08));
    cVar1 = pcVar12[1];
    if (cVar1 == '\x02') {
      iVar13 = FUN_8001ffb4((int)*(short *)(iVar13 + 0x1a));
      if (iVar13 == 0) {
        FUN_8000bb18(param_1,199);
        pcVar12[1] = '\x01';
      }
    }
    else if (cVar1 < '\x02') {
      if (cVar1 == '\0') {
        if ((*pcVar12 != '\0') && (dVar15 <= (double)*(float *)(param_1 + 0x10))) {
          FUN_8000bb18(param_1,199);
          pcVar12[1] = '\x03';
        }
      }
      else if (-1 < cVar1) {
        *(float *)(param_1 + 0x10) = FLOAT_803e6e04 * FLOAT_803db414 + *(float *)(param_1 + 0x10);
        if (*(float *)(iVar13 + 0xc) < *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = *(float *)(iVar13 + 0xc);
          pcVar12[1] = '\0';
        }
      }
    }
    else if ((cVar1 < '\x04') &&
            (*(float *)(param_1 + 0x10) =
                  -(FLOAT_803e6e04 * FLOAT_803db414 - *(float *)(param_1 + 0x10)),
            (double)*(float *)(param_1 + 0x10) < dVar15)) {
      FUN_800200e8((int)*(short *)(iVar13 + 0x1a),1);
      pcVar12[1] = '\x02';
      *(float *)(param_1 + 0x10) = (float)dVar15;
    }
    puVar5 = (uint *)FUN_800394ac(param_1,0,0);
    if (puVar5 != (uint *)0x0) {
      *puVar5 = (uint)(pcVar12[1] == '\x02');
      *puVar5 = *puVar5 << 8;
    }
  }
  else {
    FUN_80137948(s__Avitvate__i_8032b220,(int)*(short *)(iVar13 + 0x20));
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  return;
}

