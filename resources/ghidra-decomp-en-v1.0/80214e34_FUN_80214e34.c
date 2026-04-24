// Function: FUN_80214e34
// Entry: 80214e34
// Size: 236 bytes

void FUN_80214e34(int param_1)

{
  int iVar1;
  int iVar2;
  
  DAT_803ddd58 = *(undefined4 *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,DAT_803ddd58,0);
  FUN_800139c8(*DAT_803ddd54);
  if (DAT_803ddd48 != 0) {
    FUN_80013e2c();
  }
  if (DAT_803ddd54[0x5e] != 0) {
    FUN_8001f384();
  }
  iVar1 = 0;
  iVar2 = 0;
  do {
    if (*(int *)((int)DAT_803ddd54 + iVar2 + 0x17c) != 0) {
      FUN_80023800();
    }
    iVar2 = iVar2 + 4;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  DAT_803ddd48 = 0;
  FUN_8000a518(0x28,0);
  FUN_8000a518(0x93,0);
  FUN_8000a518(0x94,0);
  return;
}

