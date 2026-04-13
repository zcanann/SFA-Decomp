// Function: FUN_802430ec
// Entry: 802430ec
// Size: 28 bytes

undefined4 FUN_802430ec(uint param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(&DAT_803adfd0 + (param_1 & 0xffff) * 4);
  *(undefined4 *)(&DAT_803adfd0 + (param_1 & 0xffff) * 4) = param_2;
  return uVar1;
}

