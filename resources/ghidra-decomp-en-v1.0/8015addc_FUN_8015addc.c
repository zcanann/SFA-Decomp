// Function: FUN_8015addc
// Entry: 8015addc
// Size: 140 bytes

void FUN_8015addc(short *param_1,int param_2)

{
  if (*(char *)(param_2 + 0x33b) != '\0') {
    FUN_80036fa4(param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 0;
  }
  *param_1 = (short)(int)-(FLOAT_803e2cd8 * FLOAT_803db414 -
                          (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                 DOUBLE_803e2ce0));
  return;
}

