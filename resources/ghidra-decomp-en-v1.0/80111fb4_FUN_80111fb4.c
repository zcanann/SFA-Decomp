// Function: FUN_80111fb4
// Entry: 80111fb4
// Size: 228 bytes

void FUN_80111fb4(undefined4 param_1,int param_2,byte param_3)

{
  FUN_8000b7bc(param_1,0x7f);
  if ((param_3 & *(byte *)(param_2 + 0x404)) == 0) {
    if ((int)*(short *)(param_2 + 0x3fc) != 0) {
      (**(code **)(*DAT_803dca74 + 8))(param_1,(int)*(short *)(param_2 + 0x3fc) & 0xffff,0,0,0);
    }
    if ((int)*(short *)(param_2 + 0x3fa) != 0) {
      (**(code **)(*DAT_803dca74 + 8))(param_1,(int)*(short *)(param_2 + 0x3fa) & 0xffff,0,0,0);
    }
  }
  FUN_80012848(param_2 + 900);
  if (*(int *)(param_2 + 0x3dc) != 0) {
    FUN_80023800();
    *(undefined4 *)(param_2 + 0x3dc) = 0;
  }
  return;
}

