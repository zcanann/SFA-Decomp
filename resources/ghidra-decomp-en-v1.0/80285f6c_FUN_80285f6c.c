// Function: FUN_80285f6c
// Entry: 80285f6c
// Size: 72 bytes

void FUN_80285f6c(void)

{
  code **ppcVar1;
  undefined4 *puVar2;
  
  while (DAT_803de3e0 != (int *)0x0) {
    ppcVar1 = (code **)(DAT_803de3e0 + 1);
    puVar2 = DAT_803de3e0 + 2;
    DAT_803de3e0 = (int *)*DAT_803de3e0;
    (**ppcVar1)(*puVar2,0xffffffff);
  }
  return;
}

