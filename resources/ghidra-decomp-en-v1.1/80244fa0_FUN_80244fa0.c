// Function: FUN_80244fa0
// Entry: 80244fa0
// Size: 632 bytes

bool FUN_80244fa0(int param_1,int param_2,int param_3)

{
  ushort uVar1;
  uint uVar2;
  bool bVar7;
  undefined4 uVar3;
  undefined2 *puVar4;
  int iVar5;
  int iVar6;
  uint uVar8;
  undefined4 *puVar9;
  uint unaff_r31;
  ulonglong uVar10;
  undefined8 uVar11;
  
  FUN_802464f8();
  FUN_80241fc4();
  if (param_1 == 2) {
    bVar7 = FUN_8024fda0(1);
    unaff_r31 = (uint)bVar7;
  }
  do {
    uVar8 = 0;
    for (puVar9 = DAT_803deae0; puVar9 != (undefined4 *)0x0; puVar9 = (undefined4 *)puVar9[2]) {
      uVar3 = (*(code *)*puVar9)(0);
      uVar2 = countLeadingZeros(uVar3);
      uVar8 = uVar8 | uVar2 >> 5;
    }
    uVar3 = FUN_80245c88();
    uVar2 = countLeadingZeros(uVar3);
  } while (uVar8 != 0 || uVar2 >> 5 != 0);
  if ((param_1 == 1) && (param_3 != 0)) {
    puVar4 = FUN_80245880();
    *(byte *)((int)puVar4 + 0x13) = *(byte *)((int)puVar4 + 0x13) | 0x40;
    FUN_80245c40(1);
    do {
      iVar5 = FUN_80245c88();
    } while (iVar5 == 0);
  }
  uVar10 = FUN_80243e74();
  uVar3 = (undefined4)uVar10;
  for (puVar9 = DAT_803deae0; puVar9 != (undefined4 *)0x0; puVar9 = (undefined4 *)puVar9[2]) {
    uVar11 = (*(code *)*puVar9)(1,uVar3);
    uVar3 = (undefined4)uVar11;
    countLeadingZeros((int)((ulonglong)uVar11 >> 0x20));
  }
  FUN_80245c88();
  FUN_80242338();
  if (param_1 == 1) {
    FUN_80243e74();
    DAT_cc002002 = 0;
    FUN_80242210();
    thunk_FUN_80244eec(param_2 << 3);
    iVar5 = DAT_800000dc;
  }
  else {
    iVar5 = DAT_800000dc;
    if (param_1 == 0) {
      while (iVar6 = iVar5, iVar6 != 0) {
        uVar1 = *(ushort *)(iVar6 + 0x2c8);
        iVar5 = *(int *)(iVar6 + 0x2fc);
        if ((uVar1 == 4) || ((uVar1 < 4 && (uVar1 == 1)))) {
          FUN_80246c10(iVar6);
        }
      }
      FUN_80246538();
      FUN_80244c98();
      iVar5 = DAT_800000dc;
    }
  }
  while (iVar6 = iVar5, iVar6 != 0) {
    uVar1 = *(ushort *)(iVar6 + 0x2c8);
    iVar5 = *(int *)(iVar6 + 0x2fc);
    if ((uVar1 == 4) || ((uVar1 < 4 && (uVar1 == 1)))) {
      FUN_80246c10(iVar6);
    }
  }
  FUN_800033a8(-0x7fffffc0,0,0x8c);
  FUN_800033a8(-0x7fffff2c,0,0x14);
  FUN_800033a8(-0x7fffff0c,0,4);
  FUN_800033a8(-0x7fffd000,0,0xc0);
  FUN_800033a8(-0x7fffcf38,0,0xc);
  FUN_800033a8(-0x7fffcf1e,0,1);
  bVar7 = FUN_8024fda0(unaff_r31);
  return bVar7;
}

