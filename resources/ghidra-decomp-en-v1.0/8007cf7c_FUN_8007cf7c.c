// Function: FUN_8007cf7c
// Entry: 8007cf7c
// Size: 1780 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8007cf7c(void)

{
  byte bVar1;
  char cVar2;
  double dVar3;
  undefined auStack256 [4];
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  undefined auStack164 [48];
  undefined auStack116 [12];
  undefined4 local_68;
  undefined4 local_58;
  undefined auStack68 [28];
  undefined4 local_28;
  
  FUN_8006cabc(&local_f4,&local_f8);
  FUN_8006c6f0(0);
  FUN_80257f10(0,0,0,0x1e,0,0x7d);
  FUN_8006c5e4(&local_f0);
  FUN_8004c2e4(local_f0,1);
  dVar3 = (double)FLOAT_803deee4;
  FUN_80247318(dVar3,dVar3,dVar3,auStack68);
  local_28 = local_f4;
  FUN_8025d160(auStack68,0x27,1);
  FUN_80257f10(1,1,4,0x27,0,0x7d);
  local_bc = FLOAT_803deef8;
  local_b8 = FLOAT_803deedc;
  local_b4 = FLOAT_803deedc;
  local_b0 = FLOAT_803deedc;
  local_ac = FLOAT_803deef8;
  local_a8 = FLOAT_803deedc;
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_bc,0xfffffffe);
  FUN_8025b1e8(0,0,0,7,1,6,6,0,0,0);
  dVar3 = (double)FLOAT_803def40;
  FUN_80247318(dVar3,dVar3,dVar3,auStack116);
  FUN_802470c8((double)FLOAT_803deef0,auStack164,0x7a);
  FUN_80246eb4(auStack164,auStack116,auStack116);
  local_68 = local_f8;
  local_58 = local_f8;
  FUN_8025d160(auStack116,0x2a,1);
  FUN_80257f10(2,1,4,0x2a,0,0x7d);
  local_d4 = FLOAT_803def84;
  local_d0 = FLOAT_803def84;
  local_cc = FLOAT_803deedc;
  local_c8 = FLOAT_803def88;
  local_c4 = FLOAT_803def84;
  local_c0 = FLOAT_803deedc;
  FUN_8025b5b8(1,2,1);
  FUN_8025b3e4(1,0,0);
  FUN_8025b284(2,&local_d4,0xfffffffc);
  FUN_8025b1e8(1,1,0,7,2,0,0,1,0,0);
  cVar2 = FUN_8004c248();
  if (cVar2 == '\0') {
    (**(code **)(*DAT_803dca58 + 0x40))
              (&DAT_803db67c,0x803db67d,0x803db67e,auStack256,auStack256,auStack256);
    bVar1 = (byte)((int)((_DAT_803db67c & 0xff0000) >> 0x10) >> 3);
    _DAT_803db67c =
         (ushort)((uint)(((int)(_DAT_803db67c >> 0x18) >> 3) << 0x18) >> 0x10) | (ushort)bVar1;
    _DAT_803db67c =
         CONCAT31(CONCAT21(_DAT_803db67c,
                           (char)((int)((CONCAT12(bVar1,(short)_DAT_803db67c) & 0xff00) >> 8) >> 3))
                  ,DAT_803db678);
  }
  else {
    _DAT_803db67c =
         CONCAT31(CONCAT21(CONCAT11(DAT_803dd01c._0_1_,DAT_803dd01c._1_1_),DAT_803dd01c._2_1_),0x80)
    ;
  }
  local_fc = _DAT_803db67c;
  FUN_8025bdac(0,&local_fc);
  FUN_8025be8c(1,0x1c);
  FUN_8025be20(1,0xc);
  FUN_8025b6f0(2);
  FUN_80259e58(1);
  FUN_802581e0(4);
  FUN_8025c2a0(4);
  FUN_8025c0c4(0,0xff,0xff,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025c0c4(1,0,0,0xff);
  FUN_8025ba40(1,0xe,0xf,0xf,8);
  FUN_8025bac0(1,7,7,7,6);
  FUN_8025bef8(1,0,0);
  cVar2 = FUN_8004c248();
  if (cVar2 == '\0') {
    FUN_8025bb44(1,0,0,0,1,1);
  }
  else {
    FUN_8025bb44(1,0,0,3,1,1);
  }
  FUN_8025bc04(1,0,0,0,1,1);
  local_ec = FLOAT_803deedc;
  local_e8 = FLOAT_803deef8;
  local_e4 = FLOAT_803deedc;
  local_e0 = FLOAT_803deef4;
  local_dc = FLOAT_803deedc;
  local_d8 = FLOAT_803deedc;
  FUN_8025b284(3,&local_ec,0xfffffffb);
  FUN_8025b1e8(2,0,0,7,2,6,6,0,0,0);
  FUN_8025b1e8(3,1,0,7,3,0,0,1,0,0);
  FUN_80257f10(3,0,0,0x21,0,0x7d);
  FUN_8025c0c4(2,0xff,0xff,4);
  FUN_8025ba40(2,0xf,0xf,0xf,0xf);
  FUN_8025bac0(2,7,7,7,7);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  FUN_8025c0c4(3,3,0,4);
  FUN_8025ba40(3,8,2,3,0xf);
  FUN_8025bac0(3,7,7,7,5);
  FUN_8025bef8(3,0,0);
  FUN_8025bb44(3,0,0,0,1,0);
  FUN_8025bc04(3,0,0,0,1,0);
  FUN_8025c584(1,4,5,5);
  FUN_80258b24(0);
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

