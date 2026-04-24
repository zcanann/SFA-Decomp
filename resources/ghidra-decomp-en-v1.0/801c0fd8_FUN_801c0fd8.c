// Function: FUN_801c0fd8
// Entry: 801c0fd8
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x801c1198) */

void FUN_801c0fd8(void)

{
  float fVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack72 [16];
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar2 = (int *)FUN_802860dc();
  iVar3 = *piVar2;
  if (*(char *)(piVar2 + 0xd) < -0x32) {
    *(undefined *)((int)piVar2 + 0x35) = 1;
  }
  if ('2' < *(char *)(piVar2 + 0xd)) {
    *(undefined *)((int)piVar2 + 0x35) = 2;
  }
  if (*(char *)((int)piVar2 + 0x35) == '\x02') {
    *(char *)(piVar2 + 0xd) = *(char *)(piVar2 + 0xd) + -1;
  }
  else {
    *(char *)(piVar2 + 0xd) = *(char *)(piVar2 + 0xd) + '\x01';
  }
  fVar1 = FLOAT_803e4df8;
  dVar9 = DOUBLE_803e4df0;
  iVar5 = iVar3;
  for (iVar4 = 1; iVar4 < (int)(*(byte *)(piVar2 + 2) - 1); iVar4 = iVar4 + 1) {
    uStack52 = (int)*(char *)(piVar2 + 0xd) ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar5 + 0x4c) =
         fVar1 * (float)((double)CONCAT44(0x43300000,uStack52) - dVar9) + *(float *)(iVar5 + 0x4c);
    iVar5 = iVar5 + 0x34;
  }
  dVar9 = (double)FLOAT_803e4dfc;
  for (iVar5 = 0; fVar1 = FLOAT_803e4dfc, iVar5 < piVar2[10]; iVar5 = iVar5 + 1) {
    pfVar6 = (float *)piVar2[1];
    for (iVar4 = 0; iVar4 < (int)(*(byte *)(piVar2 + 2) - 1); iVar4 = iVar4 + 1) {
      FUN_80247754(pfVar6[1],pfVar6[2],auStack72);
      dVar8 = (double)FUN_802477f0(auStack72);
      *pfVar6 = (float)dVar8;
      if (pfVar6[5] < *pfVar6) {
        pfVar6[3] = FLOAT_803e4dfc;
      }
      if (dVar9 == (double)pfVar6[3]) {
        pfVar6[8] = (float)dVar9;
        pfVar6[7] = (float)dVar9;
        pfVar6[6] = (float)dVar9;
      }
      else {
        FUN_80247778((double)(-pfVar6[4] * (float)((double)*pfVar6 - (double)pfVar6[3])),auStack72,
                     pfVar6 + 6);
      }
      pfVar6 = pfVar6 + 9;
    }
    FUN_801c0e60(piVar2);
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(piVar2 + 2); iVar5 = iVar5 + 1) {
    *(float *)(iVar3 + 0x18) = fVar1;
    *(float *)(iVar3 + 0x1c) = fVar1;
    *(float *)(iVar3 + 0x20) = fVar1;
    iVar3 = iVar3 + 0x34;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128();
  return;
}

