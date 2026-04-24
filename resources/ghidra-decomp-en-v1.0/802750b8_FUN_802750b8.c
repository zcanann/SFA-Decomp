// Function: FUN_802750b8
// Entry: 802750b8
// Size: 96 bytes

undefined4 FUN_802750b8(undefined2 param_1)

{
  undefined4 uVar1;
  
  uRam803de2c0 = param_1;
  DAT_803de2c4 = (undefined4 *)
                 FUN_80282ee8(&DAT_803de2bc,&DAT_803c4278,DAT_803de28c,8,&LAB_80275048);
  if (DAT_803de2c4 == (undefined4 *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *DAT_803de2c4;
  }
  return uVar1;
}

