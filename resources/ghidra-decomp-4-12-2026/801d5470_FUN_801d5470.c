// Function: FUN_801d5470
// Entry: 801d5470
// Size: 232 bytes

/* WARNING: Removing unreachable block (ram,0x801d549c) */

void FUN_801d5470(uint param_1,int param_2)

{
  byte bVar1;
  
  bVar1 = *(byte *)(param_2 + 0x627);
  if (bVar1 == 1) {
    *(float *)(param_2 + 0x628) = *(float *)(param_2 + 0x628) - FLOAT_803dc074;
    if (*(float *)(param_2 + 0x628) <= FLOAT_803e60b0) {
      FUN_8000bb38(param_1,0xa8);
      *(undefined *)(param_2 + 0x627) = 2;
    }
  }
  else if (bVar1 == 0) {
    *(float *)(param_2 + 0x628) = *(float *)(param_2 + 0x628) - FLOAT_803dc074;
    if (*(float *)(param_2 + 0x628) <= FLOAT_803e60b0) {
      FUN_8000bb38(param_1,0xa9);
      *(undefined *)(param_2 + 0x627) = 1;
      *(float *)(param_2 + 0x628) = FLOAT_803e60b4;
    }
  }
  else if ((bVar1 < 3) && ((*(byte *)(param_2 + 0x625) & 1) != 0)) {
    *(undefined *)(param_2 + 0x627) = 0;
    *(float *)(param_2 + 0x628) = FLOAT_803e60b8;
  }
  return;
}

