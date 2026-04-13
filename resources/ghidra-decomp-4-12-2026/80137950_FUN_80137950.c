// Function: FUN_80137950
// Entry: 80137950
// Size: 736 bytes

/* WARNING: Removing unreachable block (ram,0x80137c10) */
/* WARNING: Removing unreachable block (ram,0x80137960) */

void FUN_80137950(void)

{
  undefined *puVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  int iStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  int iStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_80286840();
  uVar3 = FUN_80070050();
  DAT_803de674 = (ushort)(uVar3 >> 0x10);
  DAT_803de676 = (ushort)uVar3;
  FUN_8025da88(0,0,uVar3 & 0xffff,uVar3 >> 0x10);
  uVar3 = (uint)DAT_803de676;
  if (uVar3 < 0x141) {
    DAT_803de688 = 0x10;
    DAT_803de684 = uVar3 - 0x10;
  }
  else {
    DAT_803de688 = 0x20;
    DAT_803de684 = uVar3 - 0x20;
  }
  uVar3 = (uint)DAT_803de674;
  if (uVar3 < 0xf1) {
    DAT_803de680 = 0x10;
    DAT_803de67c = uVar3 - 0x10;
  }
  else {
    DAT_803de680 = 0x20;
    DAT_803de67c = uVar3 - 0x20;
  }
  FUN_80078d98();
  DAT_803de696 = (ushort)DAT_803de688;
  DAT_803de694 = (ushort)DAT_803de680;
  DAT_803de678 = 0xffffffff;
  DAT_803de690 = 0;
  DAT_803de698 = DAT_803de694;
  DAT_803de69a = DAT_803de696;
  for (puVar1 = &DAT_803aac78; puVar1 != DAT_803dc87c; puVar1 = puVar1 + iVar7) {
    DAT_803de68c = 0;
    iVar7 = FUN_80137188();
  }
  iVar7 = DAT_803de698 + 10;
  uVar6 = (uint)DAT_803de694;
  uVar9 = (uint)DAT_803de696;
  uVar3 = countLeadingZeros(DAT_803de69a - uVar9);
  uVar2 = countLeadingZeros(iVar7 - uVar6);
  if (uVar3 >> 5 == 0 && uVar2 >> 5 == 0) {
    if (1 < uVar9) {
      uVar9 = uVar9 - 2;
    }
    iVar8 = DAT_803de69a + 2;
    local_60 = 0x43300000;
    uStack_54 = (uint)DAT_803de660;
    local_58 = 0x43300000;
    dVar10 = (double)(FLOAT_803de658 +
                     (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e3038));
    uStack_5c = uVar9;
    iVar4 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar9) -
                                                        DOUBLE_803e3038) * dVar10));
    local_50 = 0x43300000;
    iStack_4c = iVar8;
    iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar8) -
                                                        DOUBLE_803e3038) * dVar10));
    local_48 = 0x43300000;
    uStack_3c = (uint)DAT_803de661;
    local_40 = 0x43300000;
    dVar10 = (double)(FLOAT_803de65c +
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3038));
    uStack_44 = uVar6;
    iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar6) -
                                                        DOUBLE_803e3038) * dVar10));
    local_38 = 0x43300000;
    iStack_34 = iVar7;
    iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar7) -
                                                        DOUBLE_803e3038) * dVar10));
    local_68 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),DAT_803de670);
    local_64 = local_68;
    FUN_80075534(iVar4,iVar5,iVar8,iVar7,&local_64);
  }
  DAT_803de69a = (ushort)DAT_803de688;
  DAT_803de698 = (ushort)DAT_803de680;
  DAT_803de678 = 0xffffffff;
  DAT_803de690 = 0;
  for (puVar1 = &DAT_803aac78; puVar1 != DAT_803dc87c; puVar1 = puVar1 + iVar7) {
    DAT_803de68c = 1;
    iVar7 = FUN_80137188();
  }
  DAT_803dc87c = &DAT_803aac78;
  DAT_803de664 = 0;
  FUN_8028688c();
  return;
}

