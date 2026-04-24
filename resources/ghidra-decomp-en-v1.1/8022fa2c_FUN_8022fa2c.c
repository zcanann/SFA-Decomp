// Function: FUN_8022fa2c
// Entry: 8022fa2c
// Size: 404 bytes

void FUN_8022fa2c(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  uint *puVar8;
  undefined8 local_20;
  
  fVar2 = FLOAT_803e7cf8;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x611) {
    if (**(char **)(param_1 + 0xb8) == '\0') {
      local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
      fVar2 = -(FLOAT_803e7cf4 * FLOAT_803dc074 - (float)(local_20 - DOUBLE_803e7d00));
    }
    else {
      fVar2 = FLOAT_803e7cf4 * FLOAT_803dc074 +
              (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) - DOUBLE_803e7d00
                     );
    }
    fVar3 = FLOAT_803e7cf8;
    if ((FLOAT_803e7cf8 <= fVar2) && (fVar3 = fVar2, FLOAT_803e7cf4 < fVar2)) {
      fVar3 = FLOAT_803e7cf4;
    }
    *(char *)(param_1 + 0x36) = (char)(int)fVar3;
    return;
  }
  if (sVar1 < 0x611) {
    if (sVar1 == 0x606) {
      puVar8 = *(uint **)(param_1 + 0xb8);
      piVar4 = (int *)FUN_8002b660(param_1);
      piVar5 = (int *)FUN_800395a4(param_1,0);
      iVar6 = FUN_800284ac(*piVar4,0);
      FUN_80054320(iVar6,(short)puVar8[1]);
      FUN_800540a8(iVar6,puVar8,piVar5);
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
  if ((FLOAT_803e7cf8 < *pfVar7) && (*pfVar7 = *pfVar7 - FLOAT_803dc074, *pfVar7 <= fVar2)) {
    *pfVar7 = fVar2;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  return;
}

