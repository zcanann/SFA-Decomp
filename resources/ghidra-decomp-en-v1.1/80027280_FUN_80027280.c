// Function: FUN_80027280
// Entry: 80027280
// Size: 236 bytes

void FUN_80027280(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined8 uVar9;
  float afStack_48 [18];
  
  uVar9 = FUN_8028683c();
  piVar2 = (int *)((ulonglong)uVar9 >> 0x20);
  pfVar5 = (float *)uVar9;
  iVar8 = *piVar2;
  iVar6 = 0;
  for (uVar7 = 0; uVar7 < *(byte *)(iVar8 + 0xf3); uVar7 = uVar7 + 1) {
    uVar4 = (uint)*(byte *)(*piVar2 + 0xf3);
    if (uVar4 == 0) {
      iVar1 = 1;
    }
    else {
      iVar1 = uVar4 + *(byte *)(*piVar2 + 0xf4);
    }
    uVar4 = uVar7;
    if (iVar1 <= (int)uVar7) {
      uVar4 = 0;
    }
    iVar1 = piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3];
    iVar3 = *(int *)(iVar8 + 0x3c) + iVar6;
    FUN_80247a48(-(double)*(float *)(iVar3 + 0x10),-(double)*(float *)(iVar3 + 0x14),
                 -(double)*(float *)(iVar3 + 0x18),afStack_48);
    FUN_80247618((float *)(iVar1 + uVar4 * 0x40),afStack_48,afStack_48);
    FUN_80248134(afStack_48,pfVar5);
    iVar6 = iVar6 + 0x1c;
    pfVar5 = pfVar5 + 0xc;
  }
  FUN_80286888();
  return;
}

