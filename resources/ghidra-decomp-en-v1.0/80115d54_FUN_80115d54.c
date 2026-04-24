// Function: FUN_80115d54
// Entry: 80115d54
// Size: 280 bytes

void FUN_80115d54(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  FUN_802860d4();
  iVar1 = FUN_802416f0();
  iVar1 = iVar1 + -0x40000;
  iVar5 = 0;
  piVar6 = &DAT_803a4438;
  do {
    *piVar6 = iVar1;
    iVar7 = *piVar6;
    *(undefined4 *)(iVar7 + 0x40) = 0;
    *(undefined *)(iVar7 + 0x48) = 0;
    iVar8 = iVar7 + 0x20;
    FUN_8025a310(iVar8,iVar7 + 0x60,*(undefined2 *)(iVar7 + 10),*(undefined2 *)(iVar7 + 0xc),
                 *(undefined *)(iVar7 + 0x16),*(undefined *)(iVar7 + 0x17),
                 *(undefined *)(iVar7 + 0x18),0);
    dVar9 = (double)FLOAT_803e1cf0;
    FUN_8025a584(dVar9,dVar9,dVar9,iVar8,*(undefined *)(iVar7 + 0x19),*(undefined *)(iVar7 + 0x1a),0
                 ,0,0);
    FUN_8025a718(iVar8,iVar7);
    uVar2 = FUN_8025a740(iVar8);
    uVar3 = FUN_8025a720(iVar8);
    uVar4 = FUN_8025a730(iVar8);
    uVar2 = FUN_8025a0ec(uVar3,uVar4,uVar2,0,0);
    *(undefined4 *)(iVar7 + 0x44) = uVar2;
    iVar1 = iVar1 + *(int *)(*piVar6 + 0x44) + 0x60;
    piVar6 = piVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 3);
  DAT_803dd5ec = 0;
  DAT_803dd5e8 = 0;
  FUN_80286120();
  return;
}

