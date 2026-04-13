// Function: FUN_80036d78
// Entry: 80036d78
// Size: 224 bytes

/* WARNING: Removing unreachable block (ram,0x80036e38) */
/* WARNING: Removing unreachable block (ram,0x80036d88) */

void FUN_80036d78(undefined4 param_1,undefined4 param_2,float *param_3)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  double dVar6;
  double dVar7;
  longlong lVar8;
  
  lVar8 = FUN_8028683c();
  iVar2 = (int)((ulonglong)lVar8 >> 0x20);
  iVar4 = 0;
  dVar7 = (double)(*param_3 * *param_3);
  if ((-1 < lVar8) && (lVar8 < 0x5400000000)) {
    uVar3 = (uint)(byte)(&DAT_80343958)[iVar2];
    bVar1 = (&DAT_80343959)[iVar2];
    piVar5 = &DAT_80343558 + uVar3;
    while ((int)uVar3 < (int)(uint)bVar1) {
      if (*piVar5 != 0) {
        dVar6 = FUN_802480c0((float *)lVar8,(float *)(*piVar5 + 0x18));
        if (dVar6 < dVar7) {
          iVar4 = *piVar5;
          dVar7 = dVar6;
        }
        piVar5 = piVar5 + 1;
        uVar3 = uVar3 + 1;
      }
    }
    if (iVar4 != 0) {
      dVar7 = FUN_80293900(dVar7);
      *param_3 = (float)dVar7;
    }
  }
  FUN_80286888();
  return;
}

