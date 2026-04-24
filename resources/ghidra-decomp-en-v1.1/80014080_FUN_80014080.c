// Function: FUN_80014080
// Entry: 80014080
// Size: 84 bytes

void FUN_80014080(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (DAT_803dbed8 != -1) {
    FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef0,DAT_803dbed8,in_r6,in_r7,in_r8,in_r9,in_r10);
    FUN_80015e00(&DAT_8033a500,0xd,0,0);
  }
  return;
}

