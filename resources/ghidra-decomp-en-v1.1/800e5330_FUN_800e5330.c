// Function: FUN_800e5330
// Entry: 800e5330
// Size: 300 bytes

/* WARNING: Removing unreachable block (ram,0x800e543c) */
/* WARNING: Removing unreachable block (ram,0x800e5434) */
/* WARNING: Removing unreachable block (ram,0x800e5348) */
/* WARNING: Removing unreachable block (ram,0x800e5340) */

void FUN_800e5330(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  double extraout_f1;
  double dVar6;
  double in_f30;
  double in_f31;
  double dVar7;
  double dVar8;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_58;
  float local_54;
  float local_50;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar9 = FUN_80286834();
  iVar1 = (int)uVar9;
  dVar7 = (double)FLOAT_803e12e4;
  local_58 = (float)extraout_f1;
  local_54 = (float)param_2;
  local_50 = (float)param_3;
  piVar5 = &DAT_803a2448;
  dVar8 = dVar7;
  for (iVar4 = 0; iVar4 < DAT_803de0f0; iVar4 = iVar4 + 1) {
    iVar3 = *piVar5;
    iVar2 = 0;
    do {
      if ((iVar1 < 1) ||
         ((int)*(char *)(iVar3 + 0x19) == *(int *)((int)((ulonglong)uVar9 >> 0x20) + iVar2 * 4))) {
        dVar6 = FUN_80021794(&local_58,(float *)(iVar3 + 8));
        if (dVar6 < dVar8) {
          dVar8 = dVar6;
        }
        iVar2 = iVar1;
        if ((*(char *)(iVar3 + 0x18) == param_6) && (dVar6 < dVar7)) {
          dVar7 = dVar6;
        }
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < iVar1);
    piVar5 = piVar5 + 1;
  }
  FUN_80286880();
  return;
}

