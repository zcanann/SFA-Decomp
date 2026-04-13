// Function: FUN_80139bbc
// Entry: 80139bbc
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x80139c90) */
/* WARNING: Removing unreachable block (ram,0x80139c88) */
/* WARNING: Removing unreachable block (ram,0x80139c80) */
/* WARNING: Removing unreachable block (ram,0x80139bdc) */
/* WARNING: Removing unreachable block (ram,0x80139bd4) */
/* WARNING: Removing unreachable block (ram,0x80139bcc) */

undefined4 FUN_80139bbc(double param_1,int param_2,float *param_3)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  uVar2 = 0;
  fVar1 = FLOAT_803e30dc * (float)(param_1 * (double)FLOAT_803dc074);
  dVar6 = (double)(fVar1 * fVar1);
  dVar4 = FUN_80021730(param_3 + 0x1a,(float *)(param_2 + 0x18));
  fVar1 = FLOAT_803e3088;
  if (param_3[0x20] != 0.0) {
    fVar1 = FLOAT_803e30d8;
  }
  dVar5 = (double)fVar1;
  iVar3 = 0;
  dVar7 = (double)FLOAT_803e30b4;
  while ((dVar4 <= dVar7 || (dVar4 <= dVar6))) {
    uVar2 = 1;
    FUN_800dabb4(dVar5,param_3);
    dVar4 = FUN_80021730(param_3 + 0x1a,(float *)(param_2 + 0x18));
    iVar3 = iVar3 + 1;
    if (4 < iVar3) {
      return 1;
    }
  }
  return uVar2;
}

