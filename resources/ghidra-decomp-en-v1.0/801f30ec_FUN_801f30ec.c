// Function: FUN_801f30ec
// Entry: 801f30ec
// Size: 116 bytes

void FUN_801f30ec(int param_1,int param_2)

{
  if ((param_2 == 0) && (**(int **)(param_1 + 0xb8) != 0)) {
    FUN_8002cbc4();
  }
  (**(code **)(*DAT_803dca7c + 0x18))(param_1);
  (**(code **)(*DAT_803dca78 + 0x14))(param_1);
  return;
}

