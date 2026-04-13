// Function: FUN_800db268
// Entry: 800db268
// Size: 260 bytes

int FUN_800db268(float *param_1,uint param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int local_18 [3];
  
  piVar5 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_18);
  iVar7 = 0;
  fVar1 = FLOAT_803e1278;
  if (0 < local_18[0]) {
    do {
      iVar6 = *piVar5;
      if ((((iVar6 != 0) && (*(char *)(iVar6 + 0x19) == '$')) &&
          ((param_2 == 0xffffffff || (*(byte *)(iVar6 + 3) == param_2)))) &&
         (((param_3 == -1 || (*(char *)(iVar6 + 0x1a) == param_3)) &&
          (fVar2 = *param_1 - *(float *)(iVar6 + 8), fVar3 = param_1[1] - *(float *)(iVar6 + 0xc),
          fVar4 = param_1[2] - *(float *)(iVar6 + 0x10),
          fVar2 = fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3, fVar2 < fVar1)))) {
        iVar7 = iVar6;
        fVar1 = fVar2;
      }
      piVar5 = piVar5 + 1;
      local_18[0] = local_18[0] + -1;
    } while (local_18[0] != 0);
  }
  return iVar7;
}

