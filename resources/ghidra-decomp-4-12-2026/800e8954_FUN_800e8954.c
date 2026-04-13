// Function: FUN_800e8954
// Entry: 800e8954
// Size: 188 bytes

void FUN_800e8954(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  if (DAT_803a3f2a == '\0') {
    param_1 = FUN_80003494((uint)DAT_803de110,0x803a3f08,0x564);
    if (DAT_803de114 != 0) {
      param_1 = FUN_80003494(DAT_803de114,0x803a3f08,0x564);
    }
  }
  if (DAT_803dc4f0 == 0xff) {
    DAT_803dc4f0 = 0;
  }
  if (*DAT_803de110 < '\x01') {
    *DAT_803de110 = '\x01';
  }
  if (DAT_803de110[0xc] < '\x01') {
    DAT_803de110[0xc] = '\x01';
  }
  FUN_8007dca0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)DAT_803dc4f0,
               DAT_803de110,&DAT_803a3e24);
  return;
}

