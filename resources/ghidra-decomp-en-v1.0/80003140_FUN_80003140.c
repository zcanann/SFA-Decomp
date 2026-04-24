// Function: FUN_80003140
// Entry: 80003140
// Size: 516 bytes

void FUN_80003140(void)

{
  undefined **ppuVar1;
  undefined4 uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  undefined8 uVar8;
  
  FUN_80003278();
  FUN_80003354();
  uVar8 = FUN_80003294();
  DAT_80000044 = 0;
  if (DAT_800000f4 == 0) {
    iVar4 = DAT_800030e8;
    if (DAT_80000034 != 0) goto LAB_800031a8;
  }
  else {
    iVar4 = *(int *)(DAT_800000f4 + 0xc);
LAB_800031a8:
    uVar2 = 0;
    if (iVar4 != 2) {
      if (iVar4 != 3) goto LAB_800031d0;
      uVar2 = 1;
    }
    FUN_8028c990((int)((ulonglong)uVar8 >> 0x20),(int)uVar8,uVar2);
  }
LAB_800031d0:
  iVar4 = DAT_800000f4;
  if ((DAT_800000f4 != 0) && (*(int *)(DAT_800000f4 + 8) != 0)) {
    piVar3 = (int *)(DAT_800000f4 + *(int *)(DAT_800000f4 + 8));
    iVar5 = *piVar3;
    if (iVar5 != 0) {
      piVar6 = piVar3 + 1;
      iVar7 = iVar5;
      do {
        piVar3 = piVar3 + 1;
        *piVar3 = *piVar3 + iVar4;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      DAT_80000034 = (uint)piVar6 & 0xffffffe0;
      goto LAB_80003238;
    }
  }
  iVar5 = 0;
  piVar6 = (int *)0x0;
LAB_80003238:
  FUN_80246d68();
  FUN_80240564();
  if (((DAT_800030e6 & 0x8000) == 0) || ((DAT_800030e6 & 0x7fff) == 1)) {
    FUN_80003100();
  }
  FUN_80246cd4();
  FUN_8002133c(iVar5,piVar6);
  if (DAT_803de3f0 == 0) {
    FUN_80285f6c();
    for (ppuVar1 = &PTR_FUN_802c18a0; (code *)*ppuVar1 != (code *)0x0;
        ppuVar1 = (code **)ppuVar1 + 1) {
      (*(code *)*ppuVar1)();
    }
    if (DAT_803de3f8 != (code *)0x0) {
      (*DAT_803de3f8)();
      DAT_803de3f8 = (code *)0x0;
    }
  }
  while (0 < DAT_803de3f4) {
    DAT_803de3f4 = DAT_803de3f4 + -1;
    (**(code **)(&DAT_803daab8 + DAT_803de3f4 * 4))();
  }
  if (DAT_803de3fc != (code *)0x0) {
    (*DAT_803de3fc)();
    DAT_803de3fc = (code *)0x0;
  }
  FUN_80246d48();
  return;
}

