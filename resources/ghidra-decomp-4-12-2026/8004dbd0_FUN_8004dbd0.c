// Function: FUN_8004dbd0
// Entry: 8004dbd0
// Size: 1704 bytes

/* WARNING: Removing unreachable block (ram,0x8004e25c) */
/* WARNING: Removing unreachable block (ram,0x8004dbe0) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8004dbd0(int param_1)

{
  float fVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  undefined4 local_140;
  float local_13c;
  float local_138;
  float local_134;
  float local_130;
  float local_12c;
  float local_128;
  int local_124;
  int local_120;
  float local_11c;
  float local_118;
  undefined4 local_114;
  float local_110;
  float local_10c;
  undefined4 local_108;
  float local_104;
  float local_100;
  undefined4 local_fc;
  float local_f8;
  float local_f4;
  undefined4 local_f0;
  float afStack_ec [12];
  float afStack_bc [12];
  float afStack_8c [3];
  float local_80;
  float local_70;
  float afStack_5c [7];
  float local_40;
  longlong local_28;
  
  local_104 = DAT_802c2548;
  local_100 = (float)DAT_802c254c;
  local_fc = DAT_802c2550;
  local_f8 = (float)DAT_802c2554;
  local_f4 = (float)DAT_802c2558;
  local_f0 = DAT_802c255c;
  local_11c = DAT_802c2560;
  local_118 = (float)DAT_802c2564;
  local_114 = DAT_802c2568;
  local_110 = (float)DAT_802c256c;
  local_10c = (float)DAT_802c2570;
  local_108 = DAT_802c2574;
  iVar2 = *(int *)(param_1 + 0x24);
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar2 + 0x20),2);
    }
    else {
      FUN_8025aeac((uint *)(iVar2 + 0x20),*(uint **)(iVar2 + 0x40),2);
    }
  }
  FUN_80258674(3,1,4,0x3c,0,0x7d);
  FUN_8006cc38(&local_128,&local_12c);
  FUN_802943c4();
  dVar3 = (double)FUN_80294964();
  fVar1 = (float)((double)FLOAT_803df788 * dVar3 + (double)FLOAT_803df784) * FLOAT_803dc250;
  local_130 = local_130 * fVar1;
  local_134 = local_134 * fVar1;
  local_f8 = -local_134;
  local_104 = local_130;
  local_100 = local_134;
  local_f4 = local_130;
  FUN_802943c4();
  dVar3 = (double)FUN_80294964();
  dVar4 = (double)(float)((double)FLOAT_803df75c * dVar3 + (double)FLOAT_803df75c);
  fVar1 = (float)((double)FLOAT_803df788 * dVar3 + (double)FLOAT_803df784) * FLOAT_803dc250;
  local_130 = local_130 * fVar1;
  local_134 = local_134 * fVar1;
  local_110 = -local_134;
  local_11c = local_130;
  local_118 = local_134;
  local_10c = local_130;
  FUN_8006c680(&local_124);
  if (local_124 != 0) {
    if (*(char *)(local_124 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_124 + 0x20),0);
    }
    else {
      FUN_8025aeac((uint *)(local_124 + 0x20),*(uint **)(local_124 + 0x40),0);
    }
  }
  if (*(byte *)(param_1 + 0x2a) == 0xff) {
    FUN_802475b8(afStack_ec);
  }
  else {
    FUN_80056d08((uint)*(byte *)(param_1 + 0x2a),&local_138,&local_13c);
    FUN_80247a48((double)local_138,(double)local_13c,(double)FLOAT_803df74c,afStack_ec);
  }
  FUN_8025d8c4(afStack_ec,0x46,0);
  FUN_80258674(0,0,4,0x3c,0,0x46);
  FUN_8006c760(&local_120);
  if (local_120 != 0) {
    if (*(char *)(local_120 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_120 + 0x20),1);
    }
    else {
      FUN_8025aeac((uint *)(local_120 + 0x20),*(uint **)(local_120 + 0x40),1);
    }
  }
  FUN_80247a7c((double)FLOAT_803df754,(double)FLOAT_803df754,(double)FLOAT_803df748,afStack_5c);
  local_40 = FLOAT_803df788 * local_12c;
  FUN_8025d8c4(afStack_5c,0x40,0);
  FUN_80258674(1,0,4,0x3c,0,0x40);
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_104,-2);
  FUN_8025b9e8(2,&local_11c,-2);
  FUN_8025b94c(1,0,0,7,1,6,6,0,0,0);
  FUN_80247a7c((double)FLOAT_803df78c,(double)FLOAT_803df78c,(double)FLOAT_803df748,afStack_8c);
  FUN_8024782c((double)FLOAT_803df790,afStack_bc,0x7a);
  FUN_80247618(afStack_bc,afStack_8c,afStack_8c);
  local_80 = FLOAT_803df794 * local_128;
  local_70 = local_80;
  FUN_8025d8c4(afStack_8c,0x43,0);
  FUN_80258674(2,0,4,0x3c,0,0x43);
  FUN_8025bd1c(1,2,1);
  FUN_8025bb48(1,0,0);
  FUN_8025b94c(2,1,0,7,2,0,0,1,0,0);
  local_28 = (longlong)(int)((double)FLOAT_803df798 * dVar4);
  _DAT_803dc24c = CONCAT13((char)(int)((double)FLOAT_803df798 * dVar4),DAT_803dc24c_1) & 0xff00ffff;
  DAT_803dc24c_1._1_2_ = (ushort)(byte)DAT_803dc24c_1;
  local_140 = _DAT_803dc24c;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_140);
  FUN_8025c5f0(0,DAT_803dd9ec);
  FUN_8025c584(1,DAT_803dd9f0);
  FUN_8025be80(0);
  FUN_8025c6b4(3,0,1,2,0);
  FUN_8025c828(0,0,2,4);
  FUN_8025c1a4(0,0xf,8,10,0xf);
  FUN_8025c224(0,6,7,7,4);
  FUN_8025c65c(0,0,3);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,1,0,2,1,0);
  DAT_803dd9b0 = 1;
  FUN_8025c828(1,0xff,0xff,0xff);
  FUN_8025c1a4(1,0xe,0xf,0xf,0);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8025c828(2,3,0,0xff);
  FUN_8025c1a4(2,0,8,1,0xf);
  FUN_8025c224(2,7,7,7,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  DAT_803dda08 = 4;
  DAT_803dda10 = 3;
  DAT_803dda0c = 3;
  DAT_803dda00 = 0x49;
  DAT_803dd9fc = 2;
  DAT_803dd9ea = 3;
  DAT_803dd9e9 = 4;
  DAT_803dd9e8 = 2;
  DAT_803dd9f4 = 1;
  DAT_803dd9f0 = 0xd;
  DAT_803dd9ec = 0x1d;
  return;
}

