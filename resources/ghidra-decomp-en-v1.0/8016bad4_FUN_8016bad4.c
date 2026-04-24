// Function: FUN_8016bad4
// Entry: 8016bad4
// Size: 52 bytes

void FUN_8016bad4(int param_1,int param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e3218);
  return;
}

