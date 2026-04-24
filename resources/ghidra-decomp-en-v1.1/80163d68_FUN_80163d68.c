// Function: FUN_80163d68
// Entry: 80163d68
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x80163e04) */
/* WARNING: Removing unreachable block (ram,0x80163d78) */

int FUN_80163d68(float *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  int local_28 [2];
  
  dVar6 = (double)FLOAT_803e3bf0;
  iVar3 = 0;
  piVar1 = FUN_80037048(0x31,local_28);
  for (iVar4 = 0; iVar4 < local_28[0]; iVar4 = iVar4 + 1) {
    iVar2 = *piVar1;
    if (((*(short *)(iVar2 + 0x46) == 0x3fb) && (1 < *(byte *)(*(int *)(iVar2 + 0xb8) + 0x278))) &&
       (dVar5 = FUN_80021794((float *)(iVar2 + 0x18),param_1), dVar5 < dVar6)) {
      iVar3 = *piVar1;
      dVar6 = dVar5;
    }
    piVar1 = piVar1 + 1;
  }
  return iVar3;
}

