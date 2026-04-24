// Function: FUN_8028429c
// Entry: 8028429c
// Size: 40 bytes

void FUN_8028429c(uint param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  uint uVar1;
  
  uVar1 = param_1 & 0xff;
  (&DAT_803cceec)[uVar1 * 0x2f] = param_2;
  (&DAT_803ccef4)[uVar1 * 0x2f] = param_3;
  (&DAT_803ccef0)[uVar1 * 0x2f] = param_4;
  (&DAT_803ccef8)[uVar1 * 0x2f] = param_5;
  return;
}

