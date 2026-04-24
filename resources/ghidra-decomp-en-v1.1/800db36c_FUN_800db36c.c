// Function: FUN_800db36c
// Entry: 800db36c
// Size: 324 bytes

/* WARNING: Removing unreachable block (ram,0x800db490) */
/* WARNING: Removing unreachable block (ram,0x800db37c) */

void FUN_800db36c(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined8 uVar11;
  int local_38 [12];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_80286838();
  pfVar4 = (float *)((ulonglong)uVar11 >> 0x20);
  piVar5 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_38);
  dVar10 = (double)FLOAT_803e1278;
  for (iVar8 = 0; iVar8 < local_38[0]; iVar8 = iVar8 + 1) {
    iVar7 = *piVar5;
    if ((((((iVar7 != 0) && (*(char *)(iVar7 + 0x19) == '$')) &&
          (((uint)uVar11 == 0xffffffff || ((uint)*(byte *)(iVar7 + 3) == (uint)uVar11)))) &&
         ((param_3 == -1 || (*(char *)(iVar7 + 0x1a) == param_3)))) &&
        (((int)*(short *)(iVar7 + 0x30) == 0xffffffff ||
         (uVar6 = FUN_80020078((int)*(short *)(iVar7 + 0x30)), uVar6 != 0)))) &&
       ((((int)*(short *)(iVar7 + 0x32) == 0xffffffff ||
         (uVar6 = FUN_80020078((int)*(short *)(iVar7 + 0x32)), uVar6 == 0)) &&
        (fVar1 = *pfVar4 - *(float *)(iVar7 + 8), fVar2 = pfVar4[1] - *(float *)(iVar7 + 0xc),
        fVar3 = pfVar4[2] - *(float *)(iVar7 + 0x10),
        dVar9 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2), dVar9 < dVar10)))) {
      dVar10 = dVar9;
    }
    piVar5 = piVar5 + 1;
  }
  FUN_80286884();
  return;
}

