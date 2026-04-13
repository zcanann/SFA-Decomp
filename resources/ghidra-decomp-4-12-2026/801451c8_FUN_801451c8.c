// Function: FUN_801451c8
// Entry: 801451c8
// Size: 272 bytes

/* WARNING: Removing unreachable block (ram,0x801452b0) */
/* WARNING: Removing unreachable block (ram,0x801452a8) */
/* WARNING: Removing unreachable block (ram,0x801451e0) */
/* WARNING: Removing unreachable block (ram,0x801451d8) */

int FUN_801451c8(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  int local_38 [2];
  
  iVar3 = 0;
  piVar1 = FUN_80037048(0x4b,local_38);
  dVar4 = FUN_80021730((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(param_1 + 0x18));
  if ((((double)FLOAT_803e31c8 <= dVar4) || (FLOAT_803e306c < *(float *)(param_2 + 0x71c))) &&
     (iVar2 = FUN_8005a288((double)FLOAT_803e3190,(float *)(param_1 + 0xc)), iVar2 == 0)) {
    dVar6 = (double)FLOAT_803e30a8;
    for (iVar2 = 0; iVar2 < local_38[0]; iVar2 = iVar2 + 1) {
      dVar5 = FUN_80021730((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(*piVar1 + 0x18));
      if ((dVar5 < dVar4) && (dVar5 < dVar6)) {
        iVar3 = *piVar1;
        dVar6 = dVar5;
      }
      piVar1 = piVar1 + 1;
    }
  }
  return iVar3;
}

