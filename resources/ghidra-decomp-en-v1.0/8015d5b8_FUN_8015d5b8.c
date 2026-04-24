// Function: FUN_8015d5b8
// Entry: 8015d5b8
// Size: 100 bytes

void FUN_8015d5b8(int param_1,char param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == -0x80) {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar1,2);
    *(undefined2 *)(iVar1 + 0x270) = 4;
    *(undefined *)(iVar1 + 0x27b) = 1;
  }
  return;
}

