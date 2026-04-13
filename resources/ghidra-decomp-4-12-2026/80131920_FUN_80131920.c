// Function: FUN_80131920
// Entry: 80131920
// Size: 116 bytes

void FUN_80131920(int param_1,int param_2)

{
  if (param_2 == 0) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xfe;
  }
  else {
    if ((*(byte *)(param_1 + 4) & 1) == 0) {
      DAT_803de598 = 0;
      FLOAT_803de59c =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xc) ^ 0x80000000) -
                  DOUBLE_803e2e78);
    }
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 1;
  }
  return;
}

