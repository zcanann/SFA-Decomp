// Function: FUN_80240564
// Entry: 80240564
// Size: 952 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80240564(void)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint *puVar5;
  
  if (DAT_803ddde8 != 0) goto LAB_80240900;
  DAT_803ddde8 = 1;
  _DAT_803dde00 = FUN_80246c70();
  FUN_8024377c();
  FUN_802403a8();
  FUN_802403d0();
  DAT_803ddddc = (uint *)0x0;
  DAT_803dddd8 = -0x80000000;
  if (DAT_800000f4 == 0) {
    if (DAT_80000034 != 0) {
      DAT_803ddde0 = (uint)DAT_800030e8._0_1_;
      DAT_803ddddc = &DAT_803ddde0;
      DAT_803ddfd4 = (uint)DAT_800030e8._1_1_;
    }
  }
  else {
    DAT_803ddddc = (uint *)(DAT_800000f4 + 0xc);
    DAT_803ddfd4 = *(uint *)(DAT_800000f4 + 0x24);
    DAT_800030e8._0_1_ = (byte)*DAT_803ddddc;
    DAT_800030e8._1_1_ = (byte)DAT_803ddfd4;
  }
  DAT_803ddefc = 1;
  iVar1 = iRam80000030;
  if (iRam80000030 == 0) {
    iVar1 = -0x7fc05b80;
  }
  FUN_80241708(iVar1);
  if (((*(int *)(DAT_803dddd8 + 0x30) == 0) && (DAT_803ddddc != (uint *)0x0)) && (*DAT_803ddddc < 2)
     ) {
    FUN_80241708(0x803f8480);
  }
  iVar1 = *(int *)(DAT_803dddd8 + 0x34);
  if (iVar1 == 0) {
    iVar1 = -0x7e900000;
  }
  FUN_80241700(iVar1);
  FUN_8024091c();
  FUN_80245bec();
  FUN_80240d34();
  FUN_80243fe8();
  FUN_802437f8();
  FUN_802437c8(0x16,&LAB_80244b50);
  FUN_80242880();
  FUN_80241f6c();
  FUN_802543bc();
  FUN_80252294();
  FUN_80245054();
  FUN_80245c50();
  FUN_80241710();
  uVar2 = FUN_80240384();
  FUN_8024038c(uVar2 & 0xbfffffff);
  puVar5 = (uint *)(DAT_803dddd8 + 0x2c);
  if ((*puVar5 & 0x10000000) == 0) {
    *puVar5 = 1;
  }
  else {
    *puVar5 = 0x10000004;
  }
  uVar2 = read_volatile_4(DAT_cc00302c);
  *(uint *)(DAT_803dddd8 + 0x2c) = *(int *)(DAT_803dddd8 + 0x2c) + (uVar2 >> 0x1c);
  if (DAT_803dddf8 == 0) {
    FUN_802443c4();
  }
  FUN_8007d6dc(s__Dolphin_OS__Revision__54____8032c360);
  FUN_8007d6dc(s_Kernel_built____s__s_8032c380,s_Jun_5_2002_8032c398,s_02_09_12_8032c3a4);
  FUN_8007d6dc(s_Console_Type___8032c3b0);
  if ((DAT_803dddd8 == 0) || (uVar2 = *(uint *)(DAT_803dddd8 + 0x2c), uVar2 == 0)) {
    uVar2 = 0x10000002;
  }
  if ((uVar2 & 0x10000000) == 0) {
    FUN_8007d6dc(s_Retail__d_8032c3c0);
  }
  else if (uVar2 == 0x10000002) {
    FUN_8007d6dc(s_EPPC_Arthur_8032c3ec);
  }
  else if ((int)uVar2 < 0x10000002) {
    if (uVar2 == 0x10000000) {
      FUN_8007d6dc(s_Mac_Emulator_8032c3cc);
    }
    else {
      if ((int)uVar2 < 0x10000000) goto LAB_80240840;
      FUN_8007d6dc(s_PC_Emulator_8032c3dc);
    }
  }
  else if ((int)uVar2 < 0x10000004) {
    FUN_8007d6dc(s_EPPC_Minnow_8032c3fc);
  }
  else {
LAB_80240840:
    FUN_8007d6dc(s_Development_HW_d_8032c40c,uVar2 + 0xeffffffd);
  }
  FUN_8007d6dc(s_Memory__d_MB_8032c420,*(uint *)(DAT_803dddd8 + 0x28) >> 0x14);
  uVar3 = FUN_802416f0();
  uVar4 = FUN_802416f8();
  FUN_8007d6dc(s_Arena___0x_x___0x_x_8032c430,uVar4,uVar3);
  if ((DAT_803ddddc != (uint *)0x0) && (1 < *DAT_803ddddc)) {
    FUN_8028cab0();
  }
  FUN_80240400();
  FUN_80243790();
  if (DAT_803dddf8 == 0) {
    FUN_802491f4();
    if (DAT_803ddde4 == 0) {
      FUN_802419b8(&DAT_803ad320,0x20);
      FUN_8024b20c(&DAT_803ad340,&DAT_803ad320,&LAB_80240528);
    }
    else {
      DAT_800030e6 = 0x9000;
    }
  }
LAB_80240900:
  DAT_803dde00 = (undefined4)((ulonglong)_DAT_803dde00 >> 0x20);
  return;
}

