// Function: FUN_8024fe60
// Entry: 8024fe60
// Size: 136 bytes

void FUN_8024fe60(undefined4 param_1,uint param_2)

{
  ushort uVar1;
  
  FUN_80243e74();
  uVar1 = DAT_cc005030;
  DAT_cc005030 = uVar1 & 0xfc00 | (ushort)((uint)param_1 >> 0x10);
  uVar1 = DAT_cc005032;
  DAT_cc005032 = uVar1 & 0x1f | (ushort)param_1;
  uVar1 = DAT_cc005036;
  DAT_cc005036 = uVar1 & 0x8000 | (ushort)(param_2 >> 5);
  FUN_80243e9c();
  return;
}

