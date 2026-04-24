// Function: FUN_801d4e80
// Entry: 801d4e80
// Size: 232 bytes

/* WARNING: Removing unreachable block (ram,0x801d4eac) */

void FUN_801d4e80(undefined4 param_1,int param_2)

{
  byte bVar1;
  
  bVar1 = *(byte *)(param_2 + 0x627);
  if (bVar1 == 1) {
    *(float *)(param_2 + 0x628) = *(float *)(param_2 + 0x628) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x628) <= FLOAT_803e5418) {
      FUN_8000bb18(param_1,0xa8);
      *(undefined *)(param_2 + 0x627) = 2;
    }
  }
  else if (bVar1 == 0) {
    *(float *)(param_2 + 0x628) = *(float *)(param_2 + 0x628) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x628) <= FLOAT_803e5418) {
      FUN_8000bb18(param_1,0xa9);
      *(undefined *)(param_2 + 0x627) = 1;
      *(float *)(param_2 + 0x628) = FLOAT_803e541c;
    }
  }
  else if ((bVar1 < 3) && ((*(byte *)(param_2 + 0x625) & 1) != 0)) {
    *(undefined *)(param_2 + 0x627) = 0;
    *(float *)(param_2 + 0x628) = FLOAT_803e5420;
  }
  return;
}

