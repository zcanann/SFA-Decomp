// Function: FUN_80131598
// Entry: 80131598
// Size: 116 bytes

void FUN_80131598(int param_1,int param_2)

{
  if (param_2 == 0) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xfe;
  }
  else {
    if ((*(byte *)(param_1 + 4) & 1) == 0) {
      DAT_803dd918 = 0;
      FLOAT_803dd91c =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xc) ^ 0x80000000) -
                  DOUBLE_803e21e8);
    }
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 1;
  }
  return;
}

