// Function: FUN_8004da54
// Entry: 8004da54
// Size: 1704 bytes

/* WARNING: Removing unreachable block (ram,0x8004e0e0) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8004da54(int param_1)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
  uint local_140;
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
  undefined auStack236 [48];
  undefined auStack188 [48];
  undefined auStack140 [12];
  float local_80;
  float local_70;
  undefined auStack92 [28];
  float local_40;
  longlong local_28;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_104 = DAT_802c1dc8;
  local_100 = (float)DAT_802c1dcc;
  local_fc = DAT_802c1dd0;
  local_f8 = (float)DAT_802c1dd4;
  local_f4 = (float)DAT_802c1dd8;
  local_f0 = DAT_802c1ddc;
  local_11c = DAT_802c1de0;
  local_118 = (float)DAT_802c1de4;
  local_114 = DAT_802c1de8;
  local_110 = (float)DAT_802c1dec;
  local_10c = (float)DAT_802c1df0;
  local_108 = DAT_802c1df4;
  iVar2 = *(int *)(param_1 + 0x24);
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025a8f0(iVar2 + 0x20,2);
    }
    else {
      FUN_8025a748(iVar2 + 0x20,*(undefined4 *)(iVar2 + 0x40),2);
    }
  }
  FUN_80257f10(3,1,4,0x3c,0,0x7d);
  FUN_8006cabc(&local_128,&local_12c);
  FUN_80293c64((double)(FLOAT_803dead8 * local_128),&local_134,&local_130);
  dVar4 = (double)FUN_80294204((double)(FLOAT_803dead8 * local_12c));
  fVar1 = (float)((double)FLOAT_803deb08 * dVar4 + (double)FLOAT_803deb04) * FLOAT_803db5f0;
  local_130 = local_130 * fVar1;
  local_134 = local_134 * fVar1;
  local_f8 = -local_134;
  local_104 = local_130;
  local_100 = local_134;
  local_f4 = local_130;
  FUN_80293c64((double)(FLOAT_803dead8 * -local_12c),&local_134,&local_130);
  dVar4 = (double)FUN_80294204((double)(FLOAT_803dead8 * local_128));
  dVar5 = (double)(float)((double)FLOAT_803deadc * dVar4 + (double)FLOAT_803deadc);
  fVar1 = (float)((double)FLOAT_803deb08 * dVar4 + (double)FLOAT_803deb04) * FLOAT_803db5f0;
  local_130 = local_130 * fVar1;
  local_134 = local_134 * fVar1;
  local_110 = -local_134;
  local_11c = local_130;
  local_118 = local_134;
  local_10c = local_130;
  FUN_8006c504(&local_124);
  if (local_124 != 0) {
    if (*(char *)(local_124 + 0x48) == '\0') {
      FUN_8025a8f0(local_124 + 0x20,0);
    }
    else {
      FUN_8025a748(local_124 + 0x20,*(undefined4 *)(local_124 + 0x40),0);
    }
  }
  if (*(char *)(param_1 + 0x2a) == -1) {
    FUN_80246e54(auStack236);
  }
  else {
    FUN_80056b8c(*(char *)(param_1 + 0x2a),&local_138,&local_13c);
    FUN_802472e4((double)local_138,(double)local_13c,(double)FLOAT_803deacc,auStack236);
  }
  FUN_8025d160(auStack236,0x46,0);
  FUN_80257f10(0,0,4,0x3c,0,0x46);
  FUN_8006c5e4(&local_120);
  if (local_120 != 0) {
    if (*(char *)(local_120 + 0x48) == '\0') {
      FUN_8025a8f0(local_120 + 0x20,1);
    }
    else {
      FUN_8025a748(local_120 + 0x20,*(undefined4 *)(local_120 + 0x40),1);
    }
  }
  FUN_80247318((double)FLOAT_803dead4,(double)FLOAT_803dead4,(double)FLOAT_803deac8,auStack92);
  local_40 = FLOAT_803deb08 * local_12c;
  FUN_8025d160(auStack92,0x40,0);
  FUN_80257f10(1,0,4,0x3c,0,0x40);
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_104,0xfffffffe);
  FUN_8025b284(2,&local_11c,0xfffffffe);
  FUN_8025b1e8(1,0,0,7,1,6,6,0,0,0);
  FUN_80247318((double)FLOAT_803deb0c,(double)FLOAT_803deb0c,(double)FLOAT_803deac8,auStack140);
  FUN_802470c8((double)FLOAT_803deb10,auStack188,0x7a);
  FUN_80246eb4(auStack188,auStack140,auStack140);
  local_80 = FLOAT_803deb14 * local_128;
  local_70 = local_80;
  FUN_8025d160(auStack140,0x43,0);
  FUN_80257f10(2,0,4,0x3c,0,0x43);
  FUN_8025b5b8(1,2,1);
  FUN_8025b3e4(1,0,0);
  FUN_8025b1e8(2,1,0,7,2,0,0,1,0,0);
  local_28 = (longlong)(int)((double)FLOAT_803deb18 * dVar5);
  _DAT_803db5ec = _DAT_803db5ec & 0xff | (int)((double)FLOAT_803deb18 * dVar5) << 0x18;
  local_140 = _DAT_803db5ec;
  FUN_8025bdac(DAT_803dcd74,&local_140);
  FUN_8025be8c(0,DAT_803dcd6c);
  FUN_8025be20(1,DAT_803dcd70);
  FUN_8025b71c(0);
  FUN_8025bf50(3,0,1,2,0);
  FUN_8025c0c4(0,0,2,4);
  FUN_8025ba40(0,0xf,8,10,0xf);
  FUN_8025bac0(0,6,7,7,4);
  FUN_8025bef8(0,0,3);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,1,0,2,1,0);
  DAT_803dcd30 = 1;
  FUN_8025c0c4(1,0xff,0xff,0xff);
  FUN_8025ba40(1,0xe,0xf,0xf,0);
  FUN_8025bac0(1,7,7,7,0);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8025c0c4(2,3,0,0xff);
  FUN_8025ba40(2,0,8,1,0xf);
  FUN_8025bac0(2,7,7,7,7);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  DAT_803dcd68 = 2;
  DAT_803dcd69 = 4;
  DAT_803dcd6a = 3;
  DAT_803dcd6c = 0x1d;
  DAT_803dcd70 = 0xd;
  DAT_803dcd74 = 1;
  DAT_803dcd7c = 2;
  DAT_803dcd80 = 0x49;
  DAT_803dcd88 = 4;
  DAT_803dcd8c = 3;
  DAT_803dcd90 = 3;
  return;
}

