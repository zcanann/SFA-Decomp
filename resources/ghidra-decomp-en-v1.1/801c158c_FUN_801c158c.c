// Function: FUN_801c158c
// Entry: 801c158c
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x801c174c) */
/* WARNING: Removing unreachable block (ram,0x801c159c) */

void FUN_801c158c(void)

{
  float fVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  float afStack_48 [4];
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  piVar2 = (int *)FUN_80286840();
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
  fVar1 = FLOAT_803e5a90;
  dVar8 = DOUBLE_803e5a88;
  iVar5 = iVar3;
  for (iVar4 = 1; iVar4 < (int)(*(byte *)(piVar2 + 2) - 1); iVar4 = iVar4 + 1) {
    uStack_34 = (int)*(char *)(piVar2 + 0xd) ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar5 + 0x4c) =
         fVar1 * (float)((double)CONCAT44(0x43300000,uStack_34) - dVar8) + *(float *)(iVar5 + 0x4c);
    iVar5 = iVar5 + 0x34;
  }
  dVar8 = (double)FLOAT_803e5a94;
  for (iVar5 = 0; fVar1 = FLOAT_803e5a94, iVar5 < piVar2[10]; iVar5 = iVar5 + 1) {
    pfVar6 = (float *)piVar2[1];
    for (iVar4 = 0; iVar4 < (int)(*(byte *)(piVar2 + 2) - 1); iVar4 = iVar4 + 1) {
      FUN_80247eb8((float *)pfVar6[1],(float *)pfVar6[2],afStack_48);
      dVar7 = FUN_80247f54(afStack_48);
      *pfVar6 = (float)dVar7;
      if (pfVar6[5] < *pfVar6) {
        pfVar6[3] = FLOAT_803e5a94;
      }
      if (dVar8 == (double)pfVar6[3]) {
        pfVar6[8] = (float)dVar8;
        pfVar6[7] = (float)dVar8;
        pfVar6[6] = (float)dVar8;
      }
      else {
        FUN_80247edc((double)(-pfVar6[4] * (float)((double)*pfVar6 - (double)pfVar6[3])),afStack_48,
                     pfVar6 + 6);
      }
      pfVar6 = pfVar6 + 9;
    }
    FUN_801c1414();
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(piVar2 + 2); iVar5 = iVar5 + 1) {
    *(float *)(iVar3 + 0x18) = fVar1;
    *(float *)(iVar3 + 0x1c) = fVar1;
    *(float *)(iVar3 + 0x20) = fVar1;
    iVar3 = iVar3 + 0x34;
  }
  FUN_8028688c();
  return;
}

