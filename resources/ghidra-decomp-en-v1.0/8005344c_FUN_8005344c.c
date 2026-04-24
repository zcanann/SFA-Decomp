// Function: FUN_8005344c
// Entry: 8005344c
// Size: 172 bytes

void FUN_8005344c(int param_1,int *param_2,int param_3)

{
  int *piVar1;
  
  if (*(int *)(param_1 + 8) != 0) {
    if (param_3 == 0) {
      piVar1 = &DAT_8037e08c;
    }
    else {
      piVar1 = &DAT_8037e000 + (6 - (*(byte *)(param_3 + 0xf2) + 1)) * 7;
    }
    *(short *)(*piVar1 + 0xe) = *(short *)(*piVar1 + 0xe) + 1;
    *param_2 = *piVar1;
  }
  if (*(int *)(param_1 + 0x14) == 0) {
    return;
  }
  if (*(byte *)(param_1 + 0x20) < 6) {
    piVar1 = &DAT_8037e000 + ((int)(uint)*(byte *)(param_1 + 0x20) >> 1) * 7;
  }
  else {
    piVar1 = &DAT_8037e000;
  }
  *(short *)(*piVar1 + 0xe) = *(short *)(*piVar1 + 0xe) + 1;
  param_2[1] = *piVar1;
  return;
}

