// Function: FUN_801e6c24
// Entry: 801e6c24
// Size: 160 bytes

void FUN_801e6c24(int param_1)

{
  uint uVar1;
  undefined *puVar2;
  int iVar3;
  
  *(undefined *)(*(int *)(param_1 + 0xb8) + 1) = 0xff;
  FUN_800372f8(param_1,9);
  iVar3 = 0;
  puVar2 = &DAT_80328c10;
  do {
    uVar1 = FUN_80022264(0,2);
    puVar2[5] = puVar2[uVar1 + 1];
    puVar2 = puVar2 + 0xc;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x3c);
  FUN_8000a538((int *)0x90,1);
  *(undefined4 *)(param_1 + 0xf8) = 0;
  FUN_800201ac(0xefe,1);
  return;
}

