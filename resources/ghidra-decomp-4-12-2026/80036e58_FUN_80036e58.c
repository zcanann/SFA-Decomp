// Function: FUN_80036e58
// Entry: 80036e58
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x80036f30) */
/* WARNING: Removing unreachable block (ram,0x80036e68) */

void FUN_80036e58(undefined4 param_1,undefined4 param_2,float *param_3)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  longlong lVar9;
  
  lVar9 = FUN_8028683c();
  iVar3 = (int)((ulonglong)lVar9 >> 0x20);
  iVar5 = 0;
  if ((-1 < lVar9) && (lVar9 < 0x5400000000)) {
    fVar2 = FLOAT_803df5e8;
    if (param_3 != (float *)0x0) {
      fVar2 = *param_3 * *param_3;
    }
    dVar8 = (double)fVar2;
    uVar4 = (uint)(byte)(&DAT_80343958)[iVar3];
    bVar1 = (&DAT_80343959)[iVar3];
    piVar6 = &DAT_80343558 + uVar4;
    for (; (int)uVar4 < (int)(uint)bVar1; uVar4 = uVar4 + 1) {
      if ((*piVar6 != (int)lVar9) &&
         (dVar7 = FUN_80021794((float *)((int)lVar9 + 0x18),(float *)(*piVar6 + 0x18)),
         dVar7 < dVar8)) {
        iVar5 = *piVar6;
        dVar8 = dVar7;
      }
      piVar6 = piVar6 + 1;
    }
    if ((iVar5 != 0) && (param_3 != (float *)0x0)) {
      dVar8 = FUN_80293900(dVar8);
      *param_3 = (float)dVar8;
    }
  }
  FUN_80286888();
  return;
}

