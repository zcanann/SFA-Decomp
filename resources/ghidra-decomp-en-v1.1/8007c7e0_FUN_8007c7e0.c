// Function: FUN_8007c7e0
// Entry: 8007c7e0
// Size: 1168 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8007c7e0(int param_1)

{
  char cVar1;
  double dVar2;
  undefined auStack_70 [4];
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float afStack_44 [15];
  
  FUN_8006c86c(0);
  FUN_8004c460(param_1,1);
  FUN_8006cc38(&uStack_60,&uStack_64);
  FUN_80258674(0,0,0,0x1e,0,0x7d);
  FUN_80258674(2,0,0,0x24,0,0x7d);
  dVar2 = (double)FLOAT_803dfb64;
  FUN_80247a7c(dVar2,dVar2,dVar2,afStack_44);
  FUN_8025d8c4(afStack_44,0x21,1);
  FUN_80258674(1,1,4,0x21,0,0x7d);
  local_5c = FLOAT_803dfb5c;
  local_58 = FLOAT_803dfb78;
  local_54 = FLOAT_803dfb5c;
  local_50 = FLOAT_803dfb5c;
  local_4c = FLOAT_803dfb5c;
  local_48 = FLOAT_803dfb78;
  cVar1 = FUN_8004c3c4();
  if (cVar1 == '\0') {
    (**(code **)(*DAT_803dd6d8 + 0x40))
              (&DAT_803dc2e8,0x803dc2e9,0x803dc2ea,auStack_70,auStack_70,auStack_70);
    _DAT_803dc2e8 =
         CONCAT31(CONCAT21(CONCAT11((char)((int)(_DAT_803dc2e8 >> 0x18) >> 3),
                                    (char)((int)(_DAT_803dc2e8 >> 0x10 & 0xff) >> 3)),
                           (char)((int)(_DAT_803dc2e8 >> 8 & 0xff) >> 3)),DAT_803dc2d8);
  }
  else {
    _DAT_803dc2e8 =
         CONCAT31(CONCAT21(CONCAT11(DAT_803ddc9c._0_1_,DAT_803ddc9c._1_1_),DAT_803ddc9c._2_1_),0x80)
    ;
  }
  local_68 = _DAT_803dc2e8;
  FUN_8025c428(3,(byte *)&local_68);
  local_6c = DAT_803dc2ec;
  FUN_8025c510(0,(byte *)&local_6c);
  FUN_8025c584(1,0xc);
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_5c,-1);
  FUN_8025b9e8(2,&local_5c,-2);
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8025b94c(1,0,0,7,2,0,0,0,0,1);
  FUN_8025be54(1);
  FUN_8025a5bc(1);
  FUN_80258944(3);
  FUN_8025ca04(2);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,6,0xf,0xf,8);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  cVar1 = FUN_8004c3c4();
  if (cVar1 == '\0') {
    FUN_8025c2a8(0,0,0,0,1,0);
  }
  else {
    FUN_8025c2a8(0,0,0,3,1,0);
  }
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025c828(1,2,0,8);
  FUN_8025c1a4(1,0,8,0xe,0xf);
  FUN_8025c224(1,7,2,5,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8025cce8(1,4,5,5);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  return;
}

