// Function: FUN_8011b5d4
// Entry: 8011b5d4
// Size: 656 bytes

void FUN_8011b5d4(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined1 *puVar4;
  int iVar5;
  double dVar6;
  undefined local_68;
  undefined local_67;
  double local_60;
  double local_58;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  local_67 = 0;
  FUN_8001b444(FUN_801358a8);
  FUN_80135820((double)FLOAT_803e1d80,(double)FLOAT_803e1d84);
  local_60 = (double)CONCAT44(0x43300000,DAT_803dd6dc);
  iVar5 = (int)((FLOAT_803dd6e0 + (float)(local_60 - DOUBLE_803e1da0)) - FLOAT_803e1d88);
  local_58 = (double)(longlong)iVar5;
  FUN_80135814(iVar5,0);
  FUN_80134d40(0xff,1,1);
  FUN_80019908(0xc0,0xc0,0xc0,0xff);
  FUN_80016870(0x3ae);
  FUN_80019908(0xff,0xff,0xff,0xff);
  FUN_8001b444(FUN_80135a90);
  FUN_80016870(0xed);
  puVar4 = &DAT_803dd6f0;
  for (iVar5 = 0; iVar5 < (int)(uint)DAT_803dd6f4; iVar5 = iVar5 + 1) {
    local_68 = *puVar4;
    FUN_80015dc8(&local_68,iVar5 + 0x2a,0,0);
    puVar4 = puVar4 + 1;
  }
  local_58 = (double)CONCAT44(0x43300000,(uint)DAT_803dd6d8);
  uStack76 = (uint)((float)(local_58 - DOUBLE_803e1da0) + FLOAT_803db414);
  local_60 = (double)(longlong)(int)uStack76;
  DAT_803dd6d8 = (ushort)uStack76;
  uStack76 = uStack76 & 0xffff;
  local_50 = 0x43300000;
  dVar6 = (double)FUN_80293e80((double)(FLOAT_803e1d9c *
                                       (float)((double)CONCAT44(0x43300000,uStack76) -
                                              DOUBLE_803e1da0)));
  iVar5 = (int)((double)FLOAT_803e1d90 * dVar6 + (double)FLOAT_803e1d8c);
  local_48 = (longlong)iVar5;
  uStack60 = (uint)DAT_803dd6d8;
  local_40 = 0x43300000;
  dVar6 = (double)FUN_80293e80((double)(FLOAT_803e1d98 *
                                       (float)((double)CONCAT44(0x43300000,uStack60) -
                                              DOUBLE_803e1da0)));
  iVar1 = (int)((double)FLOAT_803e1d90 * dVar6 + (double)FLOAT_803e1d8c);
  local_38 = (longlong)iVar1;
  uStack44 = (uint)DAT_803dd6d8;
  local_30 = 0x43300000;
  dVar6 = (double)FUN_80293e80((double)(FLOAT_803e1d94 *
                                       (float)((double)CONCAT44(0x43300000,uStack44) -
                                              DOUBLE_803e1da0)));
  iVar2 = (int)((double)FLOAT_803e1d90 * dVar6 + (double)FLOAT_803e1d8c);
  local_28 = (longlong)iVar2;
  FUN_80019908(iVar2,iVar1,iVar5,0xff);
  iVar5 = DAT_803dd6e4;
  uVar3 = FUN_80019444((&DAT_8031a880)[DAT_803dd6e4]);
  uStack28 = (&DAT_803a8690)[iVar5] + 0x8a ^ 0x80000000;
  local_20 = 0x43300000;
  iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1da8) - FLOAT_803dd6e0);
  local_18 = (longlong)iVar5;
  FUN_80015dc8(uVar3,0x56,iVar5,0);
  FUN_8001b444(0);
  FUN_80134c28(0);
  return;
}

