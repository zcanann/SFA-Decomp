// Function: FUN_802448a8
// Entry: 802448a8
// Size: 632 bytes

void FUN_802448a8(int param_1,int param_2,int param_3)

{
  ushort uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  code **ppcVar6;
  undefined4 unaff_r31;
  
  FUN_80245d94();
  FUN_802418cc();
  if (param_1 == 2) {
    unaff_r31 = FUN_8024f63c(1);
  }
  do {
    uVar5 = 0;
    for (ppcVar6 = DAT_803dde60; ppcVar6 != (code **)0x0; ppcVar6 = (code **)ppcVar6[2]) {
      uVar3 = (**ppcVar6)(0);
      uVar2 = countLeadingZeros(uVar3);
      uVar5 = uVar5 | uVar2 >> 5;
    }
    uVar3 = FUN_80245590();
    uVar2 = countLeadingZeros(uVar3);
  } while ((uVar5 | uVar2 >> 5) != 0);
  if ((param_1 == 1) && (param_3 != 0)) {
    iVar4 = FUN_80245188();
    *(byte *)(iVar4 + 0x13) = *(byte *)(iVar4 + 0x13) | 0x40;
    FUN_80245548(1);
    do {
      iVar4 = FUN_80245590();
    } while (iVar4 == 0);
  }
  FUN_8024377c();
  for (ppcVar6 = DAT_803dde60; ppcVar6 != (code **)0x0; ppcVar6 = (code **)ppcVar6[2]) {
    uVar3 = (**ppcVar6)(1);
    countLeadingZeros(uVar3);
  }
  FUN_80245590();
  FUN_80241c40();
  if (param_1 == 1) {
    FUN_8024377c();
    write_volatile_2(DAT_cc002002,0);
    FUN_80241b18();
    func_0x802447f0(param_2 << 3);
    iVar4 = DAT_800000dc;
  }
  else {
    iVar4 = DAT_800000dc;
    if (param_1 == 0) {
      while (iVar4 != 0) {
        uVar1 = *(ushort *)(iVar4 + 0x2c8);
        iVar4 = *(int *)(iVar4 + 0x2fc);
        if ((uVar1 == 4) || ((uVar1 < 4 && (uVar1 == 1)))) {
          FUN_802464ac();
        }
      }
      FUN_80245dd4();
      FUN_802445a0(param_2,param_3);
      iVar4 = DAT_800000dc;
    }
  }
  while (iVar4 != 0) {
    uVar1 = *(ushort *)(iVar4 + 0x2c8);
    iVar4 = *(int *)(iVar4 + 0x2fc);
    if ((uVar1 == 4) || ((uVar1 < 4 && (uVar1 == 1)))) {
      FUN_802464ac();
    }
  }
  FUN_800033a8(&DAT_80000040,0,0x8c);
  FUN_800033a8(&DAT_800000d4,0,0x14);
  FUN_800033a8(&DAT_800000f4,0,4);
  FUN_800033a8(&DAT_80003000,0,0xc0);
  FUN_800033a8(&DAT_800030c8,0,0xc);
  FUN_800033a8(&DAT_800030e2,0,1);
  FUN_8024f63c(unaff_r31);
  return;
}

