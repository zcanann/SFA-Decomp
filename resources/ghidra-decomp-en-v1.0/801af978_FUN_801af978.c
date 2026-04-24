// Function: FUN_801af978
// Entry: 801af978
// Size: 108 bytes

void FUN_801af978(int param_1)

{
  undefined *puVar1;
  int iVar2;
  
  puVar1 = *(undefined **)(param_1 + 0xb8);
  *puVar1 = 0xff;
  *(undefined4 *)(puVar1 + 4) = 0xffffffff;
  *(undefined4 *)(puVar1 + 8) = 0xffffffff;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  iVar2 = FUN_800e87c4();
  if (iVar2 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  return;
}

