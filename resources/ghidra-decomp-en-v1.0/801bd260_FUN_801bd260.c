// Function: FUN_801bd260
// Entry: 801bd260
// Size: 260 bytes

void FUN_801bd260(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_800200e8(0xefd,0);
  FUN_800200e8(0xc1e,1);
  FUN_800200e8(0xc1f,0);
  FUN_800200e8(0xc20,0);
  FUN_800200e8(0xd8f,0);
  FUN_800200e8(0x3e2,0);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0x7f;
  FUN_8000facc();
  FUN_80036fa4(param_1,3);
  if (*(int *)(param_1 + 200) != 0) {
    FUN_8002cbc4();
    *(undefined4 *)(param_1 + 200) = 0;
  }
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,iVar1,0x20);
  if (DAT_803ddb88 != 0) {
    FUN_80013e2c();
  }
  DAT_803ddb88 = 0;
  if (**(int **)(iVar1 + 0x40c) != 0) {
    FUN_8001f384();
  }
  FUN_80055000();
  return;
}

