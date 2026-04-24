// Function: FUN_8020c5ec
// Entry: 8020c5ec
// Size: 888 bytes

void FUN_8020c5ec(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  FUN_80089710(7,1,0);
  FLOAT_803ddd14 = FLOAT_803e65f8;
  uVar1 = (uint)(FLOAT_803e65f8 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)DAT_803dc200 - (uint)DAT_803dc1fc ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,DAT_803dc1fc ^ 0x80000000) - DOUBLE_803e6610));
  DAT_803ddd24 = (undefined)uVar1;
  uVar2 = (uint)(FLOAT_803e65f8 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc201 - (uint)bRam803dc1fd ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,bRam803dc1fd ^ 0x80000000) - DOUBLE_803e6610));
  uRam803ddd25 = (undefined)uVar2;
  uVar3 = (uint)(FLOAT_803e65f8 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc202 - (uint)bRam803dc1fe ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,bRam803dc1fe ^ 0x80000000) - DOUBLE_803e6610));
  uRam803ddd26 = (undefined)uVar3;
  FUN_800895e0(7,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff,0x40,0x40);
  uVar1 = (uint)(FLOAT_803ddd14 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)DAT_803dc1f8 - (uint)DAT_803dc1f4 ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,DAT_803dc1f4 ^ 0x80000000) - DOUBLE_803e6610));
  DAT_803ddd20 = (undefined)uVar1;
  uVar2 = (uint)(FLOAT_803ddd14 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc1f9 - (uint)bRam803dc1f5 ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,bRam803dc1f5 ^ 0x80000000) - DOUBLE_803e6610));
  uRam803ddd21 = (undefined)uVar2;
  uVar3 = (uint)(FLOAT_803ddd14 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc1fa - (uint)bRam803dc1f6 ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,bRam803dc1f6 ^ 0x80000000) - DOUBLE_803e6610));
  uRam803ddd22 = (undefined)uVar3;
  FUN_80089510(7,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff);
  uVar1 = (uint)(FLOAT_803ddd14 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)DAT_803dc208 - (uint)DAT_803dc204 ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,DAT_803dc204 ^ 0x80000000) - DOUBLE_803e6610));
  DAT_803ddd1c = (undefined)uVar1;
  uVar2 = (uint)(FLOAT_803ddd14 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc209 - (uint)bRam803dc205 ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,bRam803dc205 ^ 0x80000000) - DOUBLE_803e6610));
  uRam803ddd1d = (undefined)uVar2;
  uVar3 = (uint)(FLOAT_803ddd14 *
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)bRam803dc20a - (uint)bRam803dc206 ^ 0x80000000) -
                        DOUBLE_803e6610) +
                (float)((double)CONCAT44(0x43300000,bRam803dc206 ^ 0x80000000) - DOUBLE_803e6610));
  uRam803ddd1e = (undefined)uVar3;
  FUN_80089578(7,uVar1 & 0xff,uVar2 & 0xff,uVar3 & 0xff);
  DAT_803ddd18 = (undefined)(int)(FLOAT_803ddd14 * FLOAT_803e6600 + FLOAT_803e65fc);
  FUN_800894a8((double)FLOAT_803e6604,(double)FLOAT_803e65f8,(double)FLOAT_803e6608,7);
  return;
}

