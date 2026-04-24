// Function: FUN_8003c268
// Entry: 8003c268
// Size: 2484 bytes

/* WARNING: Removing unreachable block (ram,0x8003cbf4) */
/* WARNING: Could not reconcile some variable overlaps */

undefined4 FUN_8003c268(int param_1,undefined4 *param_2,undefined4 param_3)

{
  undefined uVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  double dVar7;
  undefined4 local_190;
  undefined4 local_18c;
  undefined4 local_188;
  undefined4 local_184;
  undefined4 local_180;
  undefined auStack380 [4];
  int local_178;
  int local_174;
  undefined4 local_170;
  float local_16c;
  float local_168;
  undefined4 local_164;
  uint local_160;
  int local_15c;
  undefined4 local_158;
  undefined4 local_154;
  float local_150;
  undefined4 local_14c;
  undefined4 local_148;
  undefined4 local_144;
  float local_140;
  float local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  float local_12c;
  undefined4 local_128;
  undefined auStack292 [48];
  float local_f4 [5];
  float local_e0;
  undefined auStack196 [48];
  undefined auStack148 [48];
  undefined auStack100 [52];
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_158 = DAT_803de9fc;
  local_13c = DAT_802c1b40;
  local_138 = DAT_802c1b44;
  local_134 = DAT_802c1b48;
  local_130 = DAT_802c1b4c;
  local_12c = (float)DAT_802c1b50;
  local_128 = DAT_802c1b54;
  local_154 = DAT_802c1b58;
  local_150 = (float)DAT_802c1b5c;
  local_14c = DAT_802c1b60;
  local_148 = DAT_802c1b64;
  local_144 = DAT_802c1b68;
  local_140 = (float)DAT_802c1b6c;
  iVar3 = FUN_80028424(*param_2,param_3);
  if ((*(uint *)(iVar3 + 0x3c) & 0x200) == 0) {
    if ((DAT_803dcc44 & 3) == 0) {
      DAT_803dcc3e = 1;
      FUN_8003d6f8(param_1);
      uVar4 = 1;
    }
    else {
      DAT_803dcc3e = 0;
      uVar4 = 0;
    }
  }
  else {
    DAT_803dcc3e = 1;
    FUN_8006c4e0(&local_15c,&local_160);
    uStack44 = DAT_803dcc44 ^ 0x80000000;
    local_30 = 0x43300000;
    uStack36 = local_160 ^ 0x80000000;
    local_28 = 0x43300000;
    fVar2 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dea40) /
            (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dea40);
    dVar7 = (double)(fVar2 * fVar2 * FLOAT_803dea28);
    puVar5 = (undefined4 *)FUN_8004c250(iVar3,0);
    uVar4 = FUN_800536c0(*puVar5);
    FUN_8004c2e4(uVar4,0);
    FUN_80257f10(2,1,4,0x3c,0,0x7d);
    FUN_8025b71c(0);
    FUN_8025c0c4(0,2,0,0xff);
    FUN_8025ba40(0,0xf,0xf,0xf,8);
    FUN_8025bac0(0,7,7,7,7);
    FUN_8025bef8(0,0,0);
    FUN_8025bb44(0,0,0,0,0,0);
    FUN_8025bc04(0,0,0,0,1,0);
    uVar1 = *(undefined *)(param_1 + 0xf1);
    local_158 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_158)));
    local_180 = local_158;
    FUN_8025bdac(0,&local_180);
    FUN_8025be8c(1,0x1c);
    FUN_8025be20(1,0xc);
    FUN_80247318((double)FLOAT_803dea2c,(double)FLOAT_803dea2c,(double)FLOAT_803dea04,auStack148);
    FUN_802472e4((double)FLOAT_803dea28,(double)FLOAT_803dea28,(double)FLOAT_803dea1c,auStack196);
    FUN_80246eb4(auStack196,auStack148,auStack148);
    FUN_8025d160(auStack148,0x43,0);
    FUN_80257f10(0,1,1,0x1e,0,0x43);
    puVar5 = (undefined4 *)FUN_800285b8(param_2,param_3);
    FUN_8004c2e4(*puVar5,1);
    FUN_8025b71c(1);
    FUN_8025c0c4(1,0,1,4);
    FUN_8025bef8(1,0,0);
    FUN_8025ba40(1,0xf,8,0xe,10);
    FUN_8025bac0(1,7,7,7,7);
    FUN_8025bb44(1,0,0,0,1,2);
    FUN_8025bc04(1,0,0,0,1,0);
    FUN_8006c5e4(&local_164);
    FUN_8004c2e4(local_164,4);
    FUN_8006cabc(&local_168,&local_16c);
    FUN_802472e4((double)(FLOAT_803dea28 * local_168),(double)(FLOAT_803dea28 * local_16c),
                 (double)FLOAT_803dea04,local_f4);
    local_f4[0] = FLOAT_803dea1c;
    local_e0 = FLOAT_803dea1c;
    FUN_8025d160(local_f4,0x46,0);
    FUN_80257f10(1,1,4,0x3c,0,0x46);
    FUN_8025b5b8(0,1,4);
    FUN_8025b3e4(0,0,0);
    local_13c = (float)dVar7;
    local_12c = (float)dVar7;
    FUN_8025b284(1,&local_13c,(int)(char)DAT_803db498);
    FUN_8025b1e8(2,0,0,7,1,6,6,0,0,0);
    FUN_8025c0c4(2,0xff,0xff,0xff);
    FUN_8025bef8(2,0,0);
    FUN_8025ba40(2,0xf,0,4,0xf);
    FUN_8025bac0(2,7,7,7,7);
    FUN_8025bb44(2,0,0,0,1,0);
    FUN_8025bc04(2,0,0,0,1,0);
    uVar4 = FUN_800536c0(*(undefined4 *)(iVar3 + 0x38));
    FUN_8004c2e4(uVar4,2);
    FUN_80257f10(3,1,4,0x3c,0,0x7d);
    FUN_8025b5b8(1,3,2);
    FUN_8025b3e4(1,0,0);
    local_150 = (float)dVar7;
    local_140 = (float)dVar7;
    FUN_8025b284(2,&local_154,(int)(char)DAT_803db49c);
    FUN_8025b1e8(3,1,0,7,2,0,0,1,0,1);
    FUN_8004c2e4(*(undefined4 *)(local_15c + DAT_803dcc44 * 4),3);
    FUN_80247318((double)FLOAT_803dea30,(double)FLOAT_803dea30,(double)FLOAT_803dea1c,auStack100);
    FUN_8025d160(auStack100,0x40,0);
    FUN_80257f10(4,1,4,0x3c,1,0x40);
    FUN_8025be20(3,4);
    FUN_8025c0c4(3,4,3,8);
    FUN_8025ba40(3,8,0xe,0,0);
    FUN_8025bac0(3,7,4,5,7);
    FUN_8025bef8(3,0,0);
    FUN_8025bb44(3,1,1,0,1,0);
    FUN_8025bc04(3,0,0,0,1,0);
    if ((int)DAT_803dcc44 < 0xc) {
      FUN_8025c2a0(4);
      FUN_8025b6f0(2);
      FUN_802581e0(5);
    }
    else {
      local_170 = DAT_803dea00;
      iVar3 = FUN_8001f4c8(param_1,0);
      if (iVar3 != 0) {
        FUN_8001db2c(iVar3,4);
        FUN_8001dc90((double)FLOAT_803dea04,(double)FLOAT_803dea34,(double)FLOAT_803dea04,iVar3);
        FUN_8001daf0(iVar3,0xff,0xff,0xff,0xff);
        FUN_8001e8f4(0);
        FUN_8001e608(2,0,0);
        local_184 = DAT_803db470;
        FUN_80259b88(2,&local_184);
        local_188 = DAT_803db468;
        FUN_80259cf0(2,&local_188);
        FUN_8001e4a4(2,iVar3,param_1);
        FUN_8001e634();
        FUN_8001f384(iVar3);
      }
      local_18c = local_170;
      FUN_8025bdac(0,&local_18c);
      FUN_8025be8c(5,0x1c);
      FUN_8025be20(5,0xc);
      FUN_8006c4c0(&local_174,&local_178,auStack380);
      FUN_8004c2e4(*(undefined4 *)
                    (local_174 + (DAT_803dcc44 + (uint)DAT_803dcc3d * local_178 + -0xc) * 4),5);
      FUN_80247318((double)FLOAT_803dea38,(double)FLOAT_803dea38,(double)FLOAT_803dea1c,auStack292);
      FUN_8025d160(auStack292,0x49,0);
      FUN_80257f10(5,1,4,0x3c,1,0x49);
      FUN_8025b71c(4);
      FUN_8025c0c4(4,5,5,4);
      FUN_8025ba40(4,0xf,0xf,0xf,0);
      FUN_8025bac0(4,7,4,5,7);
      FUN_8025bef8(4,0,0);
      FUN_8025bb44(4,0,0,0,1,0);
      FUN_8025bc04(4,0,0,0,1,2);
      FUN_8025b71c(5);
      FUN_8025c0c4(5,0xff,0xff,0xff);
      FUN_8025ba40(5,0,0xe,5,0xf);
      FUN_8025bac0(5,0,2,2,7);
      FUN_8025bef8(5,0,0);
      FUN_8025bb44(5,0,0,0,1,0);
      FUN_8025bc04(5,0,0,0,1,0);
      FUN_8025c2a0(6);
      FUN_8025b6f0(2);
      FUN_802581e0(6);
    }
    FUN_80258b24(2);
    local_190 = DAT_803db468;
    dVar7 = (double)FLOAT_803dea04;
    FUN_8025c2d4(dVar7,dVar7,dVar7,dVar7,0,&local_190);
    FUN_80070310(1,3,0);
    FUN_800702b8(1);
    FUN_8025c584(1,4,5,5);
    uVar4 = 1;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return uVar4;
}

