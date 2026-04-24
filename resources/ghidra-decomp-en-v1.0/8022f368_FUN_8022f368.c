// Function: FUN_8022f368
// Entry: 8022f368
// Size: 404 bytes

void FUN_8022f368(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  float *pfVar7;
  int iVar8;
  double local_20;
  
  fVar2 = FLOAT_803e7060;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x611) {
    if (**(char **)(param_1 + 0xb8) == '\0') {
      local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
      fVar2 = -(FLOAT_803e705c * FLOAT_803db414 - (float)(local_20 - DOUBLE_803e7068));
    }
    else {
      fVar2 = FLOAT_803e705c * FLOAT_803db414 +
              (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) - DOUBLE_803e7068
                     );
    }
    fVar3 = FLOAT_803e7060;
    if ((FLOAT_803e7060 <= fVar2) && (fVar3 = fVar2, FLOAT_803e705c < fVar2)) {
      fVar3 = FLOAT_803e705c;
    }
    *(char *)(param_1 + 0x36) = (char)(int)fVar3;
    return;
  }
  if (sVar1 < 0x611) {
    if (sVar1 == 0x606) {
      iVar8 = *(int *)(param_1 + 0xb8);
      puVar4 = (undefined4 *)FUN_8002b588();
      uVar5 = FUN_800394ac(param_1,0,0);
      uVar6 = FUN_800283e8(*puVar4,0);
      FUN_800541a4(uVar6,*(uint *)(iVar8 + 4) & 0xffff);
      FUN_80053f2c(uVar6,iVar8,uVar5);
      return;
    }
    if (sVar1 < 0x606) {
      return;
    }
    if (sVar1 < 0x610) {
      return;
    }
  }
  else if (sVar1 != 0x615) {
    return;
  }
  pfVar7 = *(float **)(param_1 + 0xb8);
  if ((FLOAT_803e7060 < *pfVar7) && (*pfVar7 = *pfVar7 - FLOAT_803db414, *pfVar7 <= fVar2)) {
    *pfVar7 = fVar2;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  return;
}

