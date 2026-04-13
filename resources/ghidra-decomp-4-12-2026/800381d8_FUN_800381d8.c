// Function: FUN_800381d8
// Entry: 800381d8
// Size: 296 bytes

/* WARNING: Removing unreachable block (ram,0x800382e0) */
/* WARNING: Removing unreachable block (ram,0x800381e8) */

void FUN_800381d8(undefined4 param_1,undefined4 param_2,float *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  double dVar6;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar7;
  int local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar7 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar2 = FUN_8002e1f4(local_34,&local_38);
  *param_3 = *param_3 * *param_3;
  if ((int)uVar7 == -1) {
    piVar4 = (int *)(iVar2 + local_34[0] * 4);
    dVar5 = (double)FLOAT_803df5f0;
    for (iVar2 = local_34[0]; iVar2 < local_38; iVar2 = iVar2 + 1) {
      dVar6 = FUN_80021794((float *)(iVar1 + 0x18),(float *)(*piVar4 + 0x18));
      if ((dVar6 != dVar5) && (dVar6 < (double)*param_3)) {
        *param_3 = (float)dVar6;
      }
      piVar4 = piVar4 + 1;
    }
  }
  else {
    piVar4 = (int *)(iVar2 + local_34[0] * 4);
    for (iVar2 = local_34[0]; iVar2 < local_38; iVar2 = iVar2 + 1) {
      iVar3 = *piVar4;
      if ((((int)uVar7 == (int)*(short *)(iVar3 + 0x46)) && (iVar1 != iVar3)) &&
         (dVar5 = FUN_80021794((float *)(iVar1 + 0x18),(float *)(iVar3 + 0x18)),
         dVar5 < (double)*param_3)) {
        *param_3 = (float)dVar5;
      }
      piVar4 = piVar4 + 1;
    }
  }
  FUN_80286888();
  return;
}

