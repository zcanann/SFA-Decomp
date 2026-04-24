// Function: FUN_8012919c
// Entry: 8012919c
// Size: 1276 bytes

void FUN_8012919c(void)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  undefined auStack232 [32];
  longlong local_c8;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  undefined4 local_a8;
  uint uStack164;
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  
  FUN_802860c8();
  iVar3 = FUN_800173c8(0x36);
  DAT_803dd7e4 = DAT_803dd7e4 + DAT_803dbaa8;
  dVar8 = (double)FUN_80293464(DAT_803dd7e4);
  iVar1 = (int)((double)FLOAT_803dbaac * dVar8 + (double)FLOAT_803dbab0);
  local_c8 = (longlong)iVar1;
  iVar6 = (int)*(short *)(iVar3 + 10);
  iVar7 = (int)*(short *)(iVar3 + 8);
  uStack100 = (uint)*(short *)(iVar3 + 0x16);
  uStack76 = (uint)*(short *)(iVar3 + 0x14);
  uStack60 = uStack76 - 5;
  uStack188 = uStack60 ^ 0x80000000;
  local_c0 = 0x43300000;
  uStack68 = uStack100 - 5;
  uStack180 = uStack68 ^ 0x80000000;
  local_b8 = 0x43300000;
  FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e1e78),
               DAT_803a89d8,0xff,0x100);
  uStack172 = uStack76 ^ 0x80000000;
  local_b0 = 0x43300000;
  uStack164 = uStack68 ^ 0x80000000;
  local_a8 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e1e78),
               DAT_803a89e4,0xff,0x100,iVar7,5,0);
  uStack156 = uStack60 ^ 0x80000000;
  local_a0 = 0x43300000;
  uStack148 = uStack100 ^ 0x80000000;
  local_98 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e1e78),
               DAT_803a89dc,0xff,0x100,5,iVar6,0);
  uStack140 = uStack76 ^ 0x80000000;
  local_90 = 0x43300000;
  uStack132 = uStack100 ^ 0x80000000;
  local_88 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e1e78),
               DAT_803a89e0,0xff,0x100,iVar7,iVar6,0);
  uStack124 = uStack76 ^ 0x80000000;
  local_80 = 0x43300000;
  uStack52 = uStack100 + iVar6;
  uStack116 = uStack52 ^ 0x80000000;
  local_78 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e1e78),
               DAT_803a89e4,0xff,0x100,iVar7,5,2);
  uStack76 = uStack76 + iVar7;
  uStack108 = uStack76 ^ 0x80000000;
  local_70 = 0x43300000;
  uStack100 = uStack100 ^ 0x80000000;
  local_68 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e1e78),
               DAT_803a89dc,0xff,0x100,5,iVar6,1);
  uStack92 = uStack76 ^ 0x80000000;
  local_60 = 0x43300000;
  uStack84 = uStack52 ^ 0x80000000;
  local_58 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e1e78),DAT_803a89d8
               ,0xff,0x100,5,5,3);
  uStack76 = uStack76 ^ 0x80000000;
  local_50 = 0x43300000;
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1e78),DAT_803a89d8
               ,0xff,0x100,5,5,1);
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1e78),
               (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1e78),DAT_803a89d8
               ,0xff,0x100,5,5,2);
  FUN_80019908(0xff,0xff,0xff,0xff);
  FUN_80016810(0x345,0,10);
  FUN_80016810(*(undefined2 *)(&DAT_8031af02 + DAT_803dba90 * 4),0,0x28);
  for (uVar5 = 0; (uVar5 & 0xff) < 5; uVar5 = uVar5 + 1) {
    puVar4 = (uint *)FUN_800e888c(DAT_803dba90,uVar5);
    bVar2 = *(byte *)((int)puVar4 + 3);
    FUN_8028f688(auStack232,&DAT_803dbba0,*puVar4 >> 1);
    if ((uVar5 & 0xff) == (uint)DAT_803dba91) {
      FUN_80019908(iVar1,iVar1,iVar1,0xff);
    }
    else if ((uVar5 & 0xff) == DAT_803dba91 + 1) {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    iVar6 = (uVar5 & 0xff) * 0x1e;
    iVar3 = iVar6 + 0x5a;
    FUN_80015dc8(puVar4 + 1,0x86,0,iVar3);
    FUN_80015dc8(auStack232,0x87,0,iVar3);
    if ((bVar2 & 1) != 0) {
      iVar7 = FUN_800173c8(0x87);
      uStack52 = (int)*(short *)(iVar7 + 0x14) + 100U ^ 0x80000000;
      local_38 = 0x43300000;
      uStack60 = *(short *)(iVar7 + 0x16) + iVar6 + 0x57U ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1e78),
                   DAT_803a8aa8,0xff,0x100);
      FUN_80015dc8(&DAT_803dbba8,0x87,0x82,iVar3);
    }
  }
  FUN_80016810(0x346,0,0x104);
  FUN_80286114();
  return;
}

