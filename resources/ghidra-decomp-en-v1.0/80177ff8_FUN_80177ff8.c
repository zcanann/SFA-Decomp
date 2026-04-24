// Function: FUN_80177ff8
// Entry: 80177ff8
// Size: 76 bytes

void FUN_80177ff8(int param_1,int param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e3610);
  FUN_80035960(param_1,1);
  return;
}

