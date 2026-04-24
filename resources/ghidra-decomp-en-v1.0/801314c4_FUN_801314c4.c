// Function: FUN_801314c4
// Entry: 801314c4
// Size: 124 bytes

void FUN_801314c4(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_8031c1b4;
  do {
    uVar1 = FUN_80054d54((int)*(short *)(puVar3 + 1));
    *puVar3 = uVar1;
    puVar3 = puVar3 + 2;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  FUN_80014b18(10);
  DAT_803dd90c = 0xff;
  FUN_8001be2c(3);
  DAT_803dd8f8 = 1;
  DAT_803dd8f9 = 0;
  return;
}

