// Function: FUN_802712c8
// Entry: 802712c8
// Size: 100 bytes

void FUN_802712c8(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803de278;
  *(undefined4 *)(param_1 + 0x28) = DAT_803de27c;
  *(undefined4 *)(param_1 + 0x24) = uVar1;
  uVar1 = DAT_803de278;
  *(undefined4 *)(param_1 + 0x30) = DAT_803de27c;
  *(undefined4 *)(param_1 + 0x2c) = uVar1;
  FUN_80271178(param_1,0,0);
  FUN_80271178(param_1,1,0);
  return;
}

