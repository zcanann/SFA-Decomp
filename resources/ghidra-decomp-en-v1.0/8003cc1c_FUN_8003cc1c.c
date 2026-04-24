// Function: FUN_8003cc1c
// Entry: 8003cc1c
// Size: 2780 bytes

/* WARNING: Removing unreachable block (ram,0x8003d6d8) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8003cc1c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  byte bVar1;
  float fVar2;
  undefined uVar3;
  bool bVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  int *piVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  int local_170;
  undefined auStack364 [4];
  undefined4 local_168;
  undefined4 local_164;
  int local_160;
  undefined auStack348 [4];
  float local_158;
  float local_154;
  undefined4 local_150;
  uint local_14c;
  int local_148;
  uint local_144;
  uint local_140;
  uint local_13c;
  uint local_138;
  undefined4 local_134;
  float local_130;
  undefined4 local_12c;
  undefined4 local_128;
  undefined4 local_124;
  float local_120;
  float local_11c;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  float local_10c;
  undefined4 local_108;
  float local_104 [5];
  float local_f0;
  undefined auStack212 [48];
  undefined auStack164 [48];
  undefined auStack116 [52];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860dc();
  iVar9 = (int)((ulonglong)uVar12 >> 0x20);
  piVar8 = (int *)uVar12;
  local_13c = DAT_803de9f4;
  local_138 = DAT_803de9f8;
  local_11c = DAT_802c1b10;
  local_118 = DAT_802c1b14;
  local_114 = DAT_802c1b18;
  local_110 = DAT_802c1b1c;
  local_10c = DAT_802c1b20;
  local_108 = DAT_802c1b24;
  local_134 = DAT_802c1b28;
  local_130 = DAT_802c1b2c;
  local_12c = DAT_802c1b30;
  local_128 = DAT_802c1b34;
  local_124 = DAT_802c1b38;
  local_120 = DAT_802c1b3c;
  iVar5 = FUN_80028424(*piVar8,param_3);
  if ((*(uint *)(iVar5 + 0x3c) & 0x200) == 0) {
    DAT_803dcc3e = 0;
    uVar6 = 0;
  }
  else {
    DAT_803dcc3e = 1;
    FUN_8006c4e0(&local_148,&local_14c);
    fVar2 = FLOAT_803dea04;
    if (DAT_803dcc35 == '\0') {
      uStack60 = DAT_803dcc44 ^ 0x80000000;
      local_40 = 0x43300000;
      uStack52 = local_14c ^ 0x80000000;
      local_38 = 0x43300000;
      fVar2 = ((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dea40) /
              (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dea40)) * FLOAT_803dea28;
    }
    dVar11 = (double)fVar2;
    puVar7 = (undefined4 *)FUN_8004c250(iVar5,0);
    uVar6 = FUN_800536c0(*puVar7);
    FUN_8004c2e4(uVar6,0);
    FUN_80257f10(2,1,4,0x3c,0,0x7d);
    if (DAT_803dcc36 == '\0') {
      FUN_8025ba40(0,0xf,0xf,0xf,8);
    }
    else {
      if (DAT_803dcc36 == '\x01') {
        uVar3 = (undefined)(DAT_803dcc44 << 4);
        ram0x803db496 = CONCAT11(uVar3,DAT_803db494_3);
        ram0x803db495 = CONCAT12(uVar3,ram0x803db496);
        _DAT_803db494 = CONCAT13(uVar3,ram0x803db495);
        FUN_8025ba40(0,8,0xc,0xe,0xf);
      }
      else {
        if ((int)DAT_803dcc44 < 8) {
          ram0x803db496 = CONCAT11((char)(DAT_803dcc44 << 5),DAT_803db494_3);
        }
        else {
          ram0x803db496 = CONCAT11(0xff,DAT_803db494_3);
        }
        _DAT_803db494 = (uint)ram0x803db496;
        ram0x803db495 = CONCAT12(ram0x803db496,ram0x803db496);
        _DAT_803db494 = CONCAT13(ram0x803db496,ram0x803db495);
        FUN_8025ba40(0,8,0xf,0xe,0xf);
      }
      local_164 = _DAT_803db494;
      FUN_8025bdac(1,&local_164);
      FUN_8025be8c(0,0x1d);
      FUN_8025be20(0,0xd);
    }
    FUN_8025b71c(0);
    FUN_8025c0c4(0,2,0,0xff);
    FUN_8025bac0(0,7,7,7,7);
    FUN_8025bef8(0,0,0);
    FUN_8025bb44(0,0,0,0,0,0);
    FUN_8025bc04(0,0,0,0,1,0);
    bVar1 = *(byte *)(iVar9 + 0xf1);
    local_13c = (uint)CONCAT12(bVar1,(ushort)bVar1);
    local_138 = (uint)CONCAT12(bVar1,*(byte *)(iVar9 + 0x37) - 0xff);
    local_144 = local_13c;
    local_140 = local_138;
    FUN_8025bd38(3,&local_144);
    FUN_80247318((double)FLOAT_803dea2c,(double)FLOAT_803dea2c,(double)FLOAT_803dea04,auStack164);
    FUN_802472e4((double)FLOAT_803dea28,(double)FLOAT_803dea28,(double)FLOAT_803dea1c,auStack212);
    FUN_80246eb4(auStack212,auStack164,auStack164);
    FUN_8025d160(auStack164,0x43,0);
    FUN_80257f10(0,1,1,0x1e,0,0x43);
    puVar7 = (undefined4 *)FUN_800285b8(piVar8,param_3);
    FUN_8004c2e4(*puVar7,1);
    FUN_8025b71c(1);
    FUN_8025c0c4(1,0,1,4);
    FUN_8025bef8(1,0,0);
    FUN_8025ba40(1,0xf,8,6,10);
    FUN_8025bac0(1,7,7,7,3);
    FUN_8025bb44(1,0,0,0,1,2);
    FUN_8025bc04(1,0,0,0,0,0);
    if ((DAT_803dcc5c == 0) || (FUN_8001d7f8(DAT_803dcc64,&local_170,auStack364), local_170 != 0)) {
      bVar4 = false;
    }
    else {
      bVar4 = true;
    }
    if (bVar4) {
      FUN_8025b71c(2);
      uVar6 = FUN_8001d818(DAT_803dcc64);
      FUN_8025d160(uVar6,0x49,0);
      FUN_80257f10(1,0,0,0,0,0x49);
      if ((DAT_803dcc60 == '\0') || (DAT_803dcc60 == '\x02')) {
        FUN_8025c0c4(2,1,5,4);
      }
      else {
        FUN_8025c0c4(2,1,5,5);
      }
      uVar6 = FUN_8001d984(DAT_803dcc64);
      FUN_8004c2e4(uVar6,5);
      FUN_8001d7f8(DAT_803dcc64,auStack348,&local_160);
      if (local_160 == 2) {
        FUN_8025ba40(2,0xf,4,8,0xf);
      }
      else if (local_160 == 3) {
        FUN_8025ba40(2,4,0xf,8,0xf);
      }
      else if (local_160 == 1) {
        FUN_8025ba40(2,0xf,0xf,8,4);
      }
      else if ((DAT_803dcc60 == '\0') || (DAT_803dcc60 == '\x01')) {
        FUN_8025ba40(2,0xf,10,8,4);
      }
      else {
        FUN_8025ba40(2,0xf,0xb,8,4);
      }
      FUN_8025bef8(2,0,0);
      if (local_160 == 1) {
        FUN_8025bb44(2,1,0,0,1,2);
      }
      else {
        FUN_8025bb44(2,0,0,0,1,2);
      }
      FUN_8025bac0(2,7,7,7,0);
      FUN_8025bc04(2,0,0,0,1,0);
      iVar9 = 3;
      uVar6 = 5;
    }
    else {
      iVar9 = 2;
      uVar6 = 1;
    }
    FUN_8006c5e4(&local_150);
    FUN_8004c2e4(local_150,4);
    FUN_8006cabc(&local_154,&local_158);
    FUN_802472e4((double)(FLOAT_803dea28 * local_154),(double)(FLOAT_803dea28 * local_158),
                 (double)FLOAT_803dea04,local_104);
    local_104[0] = FLOAT_803dea1c;
    local_f0 = FLOAT_803dea1c;
    FUN_8025d160(local_104,0x46,0);
    FUN_80257f10(uVar6,1,4,0x3c,0,0x46);
    FUN_8025b5b8(0,uVar6,4);
    FUN_8025b3e4(0,0,0);
    local_11c = (float)dVar11;
    local_10c = (float)dVar11;
    FUN_8025b284(1,&local_11c,(int)(char)DAT_803db48c);
    FUN_8025b1e8(iVar9,0,0,7,1,6,6,0,0,0);
    FUN_8025c0c4(iVar9,0xff,0xff,0xff);
    FUN_8025bef8(iVar9,0,0);
    FUN_8025ba40(iVar9,0xf,0,4,0xf);
    FUN_8025bac0(iVar9,7,7,7,0);
    FUN_8025bb44(iVar9,0,0,0,1,0);
    FUN_8025bc04(iVar9,0,0,0,0,0);
    if (*(int *)(iVar5 + 0x38) == 0) {
      FUN_8025b5b8(1,3,2);
      FUN_8025b3e4(1,0,0);
      local_130 = FLOAT_803dea04;
      local_120 = FLOAT_803dea04;
      FUN_8025b284(2,&local_134,0xfffffff1);
      FUN_8025b1e8(iVar9 + 1,1,0,7,2,0,0,1,0,0);
    }
    else {
      uVar6 = FUN_800536c0();
      FUN_8004c2e4(uVar6,2);
      FUN_80257f10(3,1,4,0x3c,0,0x7d);
      FUN_8025b5b8(1,3,2);
      FUN_8025b3e4(1,0,0);
      local_130 = (float)dVar11;
      local_120 = (float)dVar11;
      FUN_8025b284(2,&local_134,(int)(char)DAT_803db490);
      FUN_8025b1e8(iVar9 + 1,1,0,7,2,0,0,1,0,1);
    }
    FUN_8004c2e4(*(undefined4 *)(local_148 + DAT_803dcc44 * 4),3);
    FUN_80247318((double)FLOAT_803dea30,(double)FLOAT_803dea30,(double)FLOAT_803dea1c,auStack116);
    FUN_8025d160(auStack116,0x40,0);
    FUN_80257f10(4,1,4,0x3c,1,0x40);
    FUN_8025be20(iVar9 + 1,4);
    if (*(int *)(iVar5 + 0x38) == 0) {
      FUN_8025c0c4(iVar9 + 1,4,3,0xff);
      FUN_8025bac0(iVar9 + 1,4,7,7,0);
    }
    else {
      FUN_8025c0c4(iVar9 + 1,4,3,8);
      FUN_8025bac0(iVar9 + 1,7,4,5,0);
    }
    FUN_8025ba40(iVar9 + 1,8,0xe,0,0);
    FUN_8025bef8(iVar9 + 1,0,0);
    FUN_8025bb44(iVar9 + 1,1,1,0,1,0);
    FUN_8025bc04(iVar9 + 1,0,0,0,1,0);
    if (bVar4) {
      FUN_8025c2a0(5);
      FUN_802581e0(6);
    }
    else {
      FUN_8025c2a0(4);
      FUN_802581e0(5);
    }
    FUN_8025b6f0(2);
    FUN_80258b24(2);
    if ((*(ushort *)(*piVar8 + 2) & 0x100) == 0) {
      FUN_800703c4();
    }
    else {
      local_168 = DAT_803db468;
      dVar11 = (double)FLOAT_803dea04;
      FUN_8025c2d4(dVar11,dVar11,dVar11,dVar11,0,&local_168);
    }
    FUN_80070310(1,3,0);
    FUN_800702b8(1);
    FUN_8025c584(1,4,5,5);
    uVar6 = 1;
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286128(uVar6);
  return;
}

