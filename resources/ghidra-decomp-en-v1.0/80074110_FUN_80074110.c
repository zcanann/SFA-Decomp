// Function: FUN_80074110
// Entry: 80074110
// Size: 1032 bytes

/* WARNING: Could not reconcile some variable overlaps */

undefined4 FUN_80074110(int param_1,undefined4 *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  double dVar4;
  undefined4 local_68;
  undefined4 local_64;
  uint local_60;
  undefined4 local_5c;
  uint local_58;
  undefined auStack84 [52];
  undefined4 local_20;
  uint uStack28;
  
  iVar1 = FUN_80028424(*param_2,param_3);
  puVar2 = (undefined4 *)FUN_8004c250(iVar1,0);
  uVar3 = FUN_800536c0(*puVar2);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  uStack28 = FUN_8001ffb4(0x2ba);
  uStack28 = uStack28 & 0xff;
  DAT_803dd010 = (undefined)uStack28;
  local_20 = 0x43300000;
  FUN_802472e4((double)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803def00) /
                       FLOAT_803def38),(double)FLOAT_803deedc,(double)FLOAT_803deedc,auStack84);
  FUN_8025d160(auStack84,0x1e,1);
  FUN_80257f10(1,1,4,0x1e,0,0x7d);
  FUN_802581e0(2);
  FUN_8025c2a0(3);
  FUN_8025b6f0(0);
  FUN_8004c2e4(uVar3,0);
  local_58 = local_58 & 0xffffff00 |
             (uint)*(byte *)(iVar1 + 0xc) * (uint)*(byte *)(param_1 + 0x37) >> 8;
  local_60 = local_58;
  FUN_8025bdac(0,&local_60);
  FUN_8025be8c(0,0x1c);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,4,6,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  local_5c = CONCAT31(local_5c._0_3_,0x3e);
  local_64 = local_5c;
  FUN_8025bdac(1,&local_64);
  FUN_8025be8c(1,0x1d);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,1,0,0xff);
  FUN_8025ba40(1,0xf,0xf,0xf,0);
  FUN_8025bac0(1,7,6,4,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,2,1,1);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,0xff,0xff,0xff);
  FUN_8025ba40(2,0xf,0xf,0xf,0);
  FUN_8025bac0(2,0,7,1,7);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  FUN_8025c584(1,4,5,5);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_80258b24(0);
  local_68 = local_5c;
  dVar4 = (double)FLOAT_803deedc;
  FUN_8025c2d4(dVar4,dVar4,dVar4,dVar4,0,&local_68);
  return 1;
}

