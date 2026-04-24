// Function: FUN_80286bf4
// Entry: 80286bf4
// Size: 40 bytes

undefined8 FUN_80286bf4(int param_1,uint param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_2 >> param_3 | param_1 << 0x20 - param_3;
  if (0 < (int)(param_3 - 0x20)) {
    uVar1 = uVar1 | param_1 >> (param_3 - 0x20 & 0x3f);
  }
  return CONCAT44(param_1 >> (param_3 & 0x3f),uVar1);
}

