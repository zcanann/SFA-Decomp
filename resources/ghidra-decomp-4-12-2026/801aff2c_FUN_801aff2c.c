// Function: FUN_801aff2c
// Entry: 801aff2c
// Size: 108 bytes

void FUN_801aff2c(int param_1)

{
  undefined *puVar1;
  int iVar2;
  
  puVar1 = *(undefined **)(param_1 + 0xb8);
  *puVar1 = 0xff;
  *(undefined4 *)(puVar1 + 4) = 0xffffffff;
  *(undefined4 *)(puVar1 + 8) = 0xffffffff;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  iVar2 = FUN_800e8a48();
  if (iVar2 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  return;
}

