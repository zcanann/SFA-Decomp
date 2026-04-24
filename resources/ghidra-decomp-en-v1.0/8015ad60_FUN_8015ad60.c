// Function: FUN_8015ad60
// Entry: 8015ad60
// Size: 124 bytes

void FUN_8015ad60(short *param_1,int param_2)

{
  if (*(char *)(param_2 + 0x33b) == '\0') {
    FUN_80037200(param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 1;
  }
  FUN_80035df4(param_1,10,1,0);
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  *param_1 = *param_1 + -0x100;
  return;
}

