// Function: FUN_8015b288
// Entry: 8015b288
// Size: 140 bytes

void FUN_8015b288(short *param_1,int param_2)

{
  if (*(char *)(param_2 + 0x33b) != '\0') {
    FUN_8003709c((int)param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 0;
  }
  *param_1 = (short)(int)-(FLOAT_803e3970 * FLOAT_803dc074 -
                          (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                 DOUBLE_803e3978));
  return;
}

