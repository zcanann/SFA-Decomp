// Function: FUN_8025aa64
// Entry: 8025aa64
// Size: 72 bytes

void FUN_8025aa64(uint *param_1,int param_2,int param_3)

{
  *param_1 = 0;
  *param_1 = *param_1 & 0xfffffc00 | param_2 - 0x80000U >> 9;
  *param_1 = *param_1 & 0xffe003ff | param_3 << 10;
  *param_1 = *param_1 & 0xffffff | 0x65000000;
  return;
}

