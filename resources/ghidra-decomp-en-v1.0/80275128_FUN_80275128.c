// Function: FUN_80275128
// Entry: 80275128
// Size: 128 bytes

undefined4 FUN_80275128(undefined2 param_1,undefined2 *param_2)

{
  undefined4 uVar1;
  
  DAT_803ca29c = param_1;
  DAT_803de2c8 = (undefined4 *)
                 FUN_80282ee8(&DAT_803ca298,&DAT_803c4a78,DAT_803de28e,0xc,&LAB_80275118);
  if (DAT_803de2c8 == (undefined4 *)0x0) {
    uVar1 = 0;
  }
  else {
    *param_2 = *(undefined2 *)((int)DAT_803de2c8 + 6);
    uVar1 = *DAT_803de2c8;
  }
  return uVar1;
}

