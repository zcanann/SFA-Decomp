// Function: FUN_8007c664
// Entry: 8007c664
// Size: 1168 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8007c664(undefined4 param_1)

{
  byte bVar1;
  char cVar2;
  double dVar3;
  undefined auStack112 [4];
  undefined4 local_6c;
  undefined4 local_68;
  undefined auStack100 [4];
  undefined auStack96 [4];
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack68 [60];
  
  FUN_8006c6f0(0);
  FUN_8004c2e4(param_1,1);
  FUN_8006cabc(auStack96,auStack100);
  FUN_80257f10(0,0,0,0x1e,0,0x7d);
  FUN_80257f10(2,0,0,0x24,0,0x7d);
  dVar3 = (double)FLOAT_803deee4;
  FUN_80247318(dVar3,dVar3,dVar3,auStack68);
  FUN_8025d160(auStack68,0x21,1);
  FUN_80257f10(1,1,4,0x21,0,0x7d);
  local_5c = FLOAT_803deedc;
  local_58 = FLOAT_803deef8;
  local_54 = FLOAT_803deedc;
  local_50 = FLOAT_803deedc;
  local_4c = FLOAT_803deedc;
  local_48 = FLOAT_803deef8;
  cVar2 = FUN_8004c248();
  if (cVar2 == '\0') {
    (**(code **)(*DAT_803dca58 + 0x40))
              (&DAT_803db688,0x803db689,0x803db68a,auStack112,auStack112,auStack112);
    bVar1 = (byte)((int)((_DAT_803db688 & 0xff0000) >> 0x10) >> 3);
    _DAT_803db688 =
         (ushort)((uint)(((int)(_DAT_803db688 >> 0x18) >> 3) << 0x18) >> 0x10) | (ushort)bVar1;
    _DAT_803db688 =
         CONCAT31(CONCAT21(_DAT_803db688,
                           (char)((int)((CONCAT12(bVar1,(short)_DAT_803db688) & 0xff00) >> 8) >> 3))
                  ,DAT_803db678);
  }
  else {
    _DAT_803db688 =
         CONCAT31(CONCAT21(CONCAT11(DAT_803dd01c._0_1_,DAT_803dd01c._1_1_),DAT_803dd01c._2_1_),0x80)
    ;
  }
  local_68 = _DAT_803db688;
  FUN_8025bcc4(3,&local_68);
  local_6c = DAT_803db68c;
  FUN_8025bdac(0,&local_6c);
  FUN_8025be20(1,0xc);
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_5c,0xffffffff);
  FUN_8025b284(2,&local_5c,0xfffffffe);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  FUN_8025b1e8(1,0,0,7,2,0,0,0,0,1);
  FUN_8025b6f0(1);
  FUN_80259e58(1);
  FUN_802581e0(3);
  FUN_8025c2a0(2);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,6,0xf,0xf,8);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  cVar2 = FUN_8004c248();
  if (cVar2 == '\0') {
    FUN_8025bb44(0,0,0,0,1,0);
  }
  else {
    FUN_8025bb44(0,0,0,3,1,0);
  }
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025c0c4(1,2,0,8);
  FUN_8025ba40(1,0,8,0xe,0xf);
  FUN_8025bac0(1,7,2,5,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8025c584(1,4,5,5);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  return;
}

