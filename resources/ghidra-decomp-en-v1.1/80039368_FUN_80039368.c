// Function: FUN_80039368
// Entry: 80039368
// Size: 128 bytes

void FUN_80039368(uint param_1,undefined *param_2,ushort param_3)

{
  bool bVar1;
  
  bVar1 = FUN_8000b598(param_1,0x10);
  if (!bVar1) {
    FUN_8000bad0(param_1,0x10,param_3);
    *(float *)(param_2 + 0xc) = FLOAT_803df648;
    *(undefined2 *)(param_2 + 0x14) = 0xfb00;
    *param_2 = 1;
    *(float *)(param_2 + 4) = FLOAT_803df61c;
  }
  return;
}

