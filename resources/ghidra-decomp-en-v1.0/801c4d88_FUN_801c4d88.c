// Function: FUN_801c4d88
// Entry: 801c4d88
// Size: 220 bytes

void FUN_801c4d88(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if ((piVar1[6] & 0x20U) != 0) {
    FUN_8011f6d4(0);
    piVar1[6] = piVar1[6] & 0xffffffdf;
  }
  if (*piVar1 != 0) {
    FUN_8001f384();
    *piVar1 = 0;
  }
  FUN_8000a518(0xd8,0);
  FUN_8000a518(0xd9,0);
  FUN_8000a518(8,0);
  FUN_8000a518(10,0);
  FUN_800200e8(0xefa,0);
  FUN_800200e8(0xcbb,1);
  FUN_800200e8(0xe82,0);
  FUN_800200e8(0xe83,0);
  FUN_800200e8(0xe84,0);
  FUN_800200e8(0xe85,0);
  return;
}

