// Function: FUN_80282550
// Entry: 80282550
// Size: 68 bytes

void FUN_80282550(uint param_1,uint param_2)

{
  undefined *puVar1;
  
  if ((param_2 & 0xff) == 0xff) {
    puVar1 = &DAT_803d4b80 + (param_1 & 0xff);
  }
  else {
    puVar1 = (undefined *)((param_2 & 0xff) * 0x10 + -0x7fc2b500 + (param_1 & 0xff));
  }
  *puVar1 = 2;
  return;
}

