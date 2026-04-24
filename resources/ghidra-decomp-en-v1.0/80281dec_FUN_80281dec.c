// Function: FUN_80281dec
// Entry: 80281dec
// Size: 68 bytes

void FUN_80281dec(uint param_1,uint param_2)

{
  undefined *puVar1;
  
  if ((param_2 & 0xff) == 0xff) {
    puVar1 = &DAT_803d3f20 + (param_1 & 0xff);
  }
  else {
    puVar1 = (undefined *)((param_2 & 0xff) * 0x10 + -0x7fc2c160 + (param_1 & 0xff));
  }
  *puVar1 = 2;
  return;
}

