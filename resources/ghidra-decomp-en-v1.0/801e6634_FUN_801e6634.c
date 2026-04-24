// Function: FUN_801e6634
// Entry: 801e6634
// Size: 160 bytes

void FUN_801e6634(int param_1)

{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  
  *(undefined *)(*(int *)(param_1 + 0xb8) + 1) = 0xff;
  FUN_80037200(param_1,9);
  iVar3 = 0;
  puVar2 = &DAT_80327fd0;
  do {
    iVar1 = FUN_800221a0(0,2);
    puVar2[5] = puVar2[iVar1 + 1];
    puVar2 = puVar2 + 0xc;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x3c);
  FUN_8000a518(0x90,1);
  *(undefined4 *)(param_1 + 0xf8) = 0;
  FUN_800200e8(0xefe,1);
  return;
}

