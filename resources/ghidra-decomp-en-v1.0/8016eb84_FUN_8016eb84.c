// Function: FUN_8016eb84
// Entry: 8016eb84
// Size: 112 bytes

void FUN_8016eb84(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  do {
    FUN_80023800(*puVar2);
    puVar2 = puVar2 + 6;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 3);
  (**(code **)(*DAT_803dca78 + 0x18))(param_1);
  return;
}

