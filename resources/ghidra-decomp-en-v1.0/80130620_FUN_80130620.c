// Function: FUN_80130620
// Entry: 80130620
// Size: 184 bytes

void FUN_80130620(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined2 *puVar3;
  
  puVar3 = &DAT_803a9458;
  for (iVar2 = 0; iVar2 < DAT_803dd911; iVar2 = iVar2 + 1) {
    puVar3[0xb] = *(undefined2 *)(param_1 + 0x16);
    *(undefined *)(puVar3 + 0xd) = *(undefined *)(param_1 + 0x1a);
    puVar3[2] = *(undefined2 *)(param_1 + 4);
    if (*(int *)(param_1 + 0x10) == -1) {
      if (*(int *)(puVar3 + 8) != 0) {
        FUN_80054308();
      }
      *(undefined4 *)(puVar3 + 8) = 0;
    }
    else if (*(int *)(puVar3 + 8) == 0) {
      uVar1 = FUN_80054d54();
      *(undefined4 *)(puVar3 + 8) = uVar1;
    }
    puVar3 = puVar3 + 0x1e;
    param_1 = param_1 + 0x3c;
  }
  return;
}

