// Function: FUN_8015ee98
// Entry: 8015ee98
// Size: 180 bytes

void FUN_8015ee98(int param_1,byte param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0x81) {
    *(byte *)(iVar1 + 0x404) = *(byte *)(iVar1 + 0x404) & 0xfb;
  }
  else if ((param_2 < 0x81) && (0x7f < param_2)) {
    *(byte *)(*(int *)(iVar1 + 0x40c) + 9) = *(byte *)(*(int *)(iVar1 + 0x40c) + 9) | 2;
    FUN_8000bb18(param_1,0x264);
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar1,1);
    *(undefined2 *)(iVar1 + 0x270) = 4;
    *(undefined *)(iVar1 + 0x27b) = 1;
  }
  return;
}

