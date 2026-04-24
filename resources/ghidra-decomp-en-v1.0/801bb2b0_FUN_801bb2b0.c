// Function: FUN_801bb2b0
// Entry: 801bb2b0
// Size: 120 bytes

undefined4 FUN_801bb2b0(int param_1,int param_2)

{
  bool bVar1;
  float fVar2;
  
  bVar1 = *(char *)(param_2 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_80030334((double)FLOAT_803e4bd8,param_1,1,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    fVar2 = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x284) = fVar2;
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
  }
  return 0;
}

