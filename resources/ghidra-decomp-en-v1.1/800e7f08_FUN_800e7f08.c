// Function: FUN_800e7f08
// Entry: 800e7f08
// Size: 84 bytes

void FUN_800e7f08(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6)

{
  *(byte *)(param_1 + 0x97) = *(byte *)(param_1 + 0x97) & 0xf0;
  *(byte *)(param_1 + 0x97) = *(byte *)(param_1 + 0x97) | param_2 & 0xf;
  *(undefined *)((int)param_1 + 0x25d) = param_5;
  *(undefined *)((int)param_1 + 0x263) = param_6;
  param_1[0x37] = param_3;
  param_1[0x38] = param_4;
  *param_1 = *param_1 | 0x2000008;
  *(undefined *)(param_1 + 0x99) = 10;
  return;
}

