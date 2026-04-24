// Function: FUN_801c533c
// Entry: 801c533c
// Size: 220 bytes

void FUN_801c533c(int param_1)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if ((puVar1[6] & 0x20) != 0) {
    FUN_8011f9b8(0);
    puVar1[6] = puVar1[6] & 0xffffffdf;
  }
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
    *puVar1 = 0;
  }
  FUN_8000a538((int *)0xd8,0);
  FUN_8000a538((int *)0xd9,0);
  FUN_8000a538((int *)0x8,0);
  FUN_8000a538((int *)0xa,0);
  FUN_800201ac(0xefa,0);
  FUN_800201ac(0xcbb,1);
  FUN_800201ac(0xe82,0);
  FUN_800201ac(0xe83,0);
  FUN_800201ac(0xe84,0);
  FUN_800201ac(0xe85,0);
  return;
}

