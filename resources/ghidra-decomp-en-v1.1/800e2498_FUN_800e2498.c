// Function: FUN_800e2498
// Entry: 800e2498
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x800e25e4) */
/* WARNING: Removing unreachable block (ram,0x800e25dc) */
/* WARNING: Removing unreachable block (ram,0x800e25d4) */
/* WARNING: Removing unreachable block (ram,0x800e25cc) */
/* WARNING: Removing unreachable block (ram,0x800e25c4) */
/* WARNING: Removing unreachable block (ram,0x800e24c8) */
/* WARNING: Removing unreachable block (ram,0x800e24c0) */
/* WARNING: Removing unreachable block (ram,0x800e24b8) */
/* WARNING: Removing unreachable block (ram,0x800e24b0) */
/* WARNING: Removing unreachable block (ram,0x800e24a8) */

int FUN_800e2498(double param_1,double param_2,double param_3,int param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  int local_78;
  undefined4 uStack_74;
  undefined8 local_70;
  
  piVar4 = (int *)FUN_8002e1f4(&uStack_74,&local_78);
  dVar9 = (double)FLOAT_803e12b0;
  dVar10 = (double)FLOAT_803e12b8;
  for (iVar7 = 0; iVar7 < local_78; iVar7 = iVar7 + 1) {
    iVar5 = *piVar4;
    if ((((*(short *)(iVar5 + 0x44) == 0x2c) && (*(char *)(iVar5 + 0xac) != param_4)) &&
        (iVar6 = *(int *)(iVar5 + 0x4c), iVar6 != 0)) &&
       ((*(char *)(iVar6 + 0x19) == '\x16' &&
        ((fVar1 = (float)((double)*(float *)(iVar5 + 0x18) - param_1),
         fVar2 = (float)((double)*(float *)(iVar5 + 0x1c) - param_2),
         fVar3 = (float)((double)*(float *)(iVar5 + 0x20) - param_3),
         dVar8 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)),
         (double)FLOAT_803e12b0 == dVar9 || (dVar8 < dVar10)))))) {
      local_70 = (double)CONCAT44(0x43300000,*(undefined4 *)(iVar6 + 0x14));
      dVar9 = (double)(float)(local_70 - DOUBLE_803e12a8);
      dVar10 = dVar8;
    }
    piVar4 = piVar4 + 1;
  }
  return (int)dVar9;
}

