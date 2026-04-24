// Function: FUN_800e8a50
// Entry: 800e8a50
// Size: 192 bytes

int FUN_800e8a50(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                byte param_9)

{
  int iVar1;
  
  DAT_803dc4f0 = param_9;
  FUN_800033a8(-0x7fc5c0f8,0,0xf70);
  if ((*(byte *)(DAT_803de110 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803de110,0,0x6ec);
  }
  iVar1 = FUN_8007ddd8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (uint)DAT_803dc4f0,DAT_803de110);
  if (iVar1 == 0) {
    FUN_800e8d40(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if (*(char *)(DAT_803de110 + 0x21) == '\0') {
    iVar1 = FUN_800e8d40(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else {
    FUN_80003494(0x803a3f08,DAT_803de110,0x6ec);
  }
  return iVar1;
}

