// Function: FUN_802429f4
// Entry: 802429f4
// Size: 28 bytes

undefined4 FUN_802429f4(uint param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(&DAT_803ad370 + (param_1 & 0xffff) * 4);
  *(undefined4 *)(&DAT_803ad370 + (param_1 & 0xffff) * 4) = param_2;
  return uVar1;
}

