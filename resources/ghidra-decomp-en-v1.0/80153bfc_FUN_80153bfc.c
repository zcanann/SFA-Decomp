// Function: FUN_80153bfc
// Entry: 80153bfc
// Size: 148 bytes

void FUN_80153bfc(int param_1,int param_2)

{
  *(byte *)(param_2 + 0x33b) = *(byte *)(param_2 + 0x33b) & 0xbf;
  if (((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) && (*(short *)(param_1 + 0xa0) != 1)) {
    FUN_8000b4d0(param_1,0x49c,2);
    FUN_8014d08c((double)FLOAT_803e290c,param_1,param_2,1,0,0);
  }
  FUN_8015355c(param_1,param_2);
  return;
}

