// Function: FUN_80039270
// Entry: 80039270
// Size: 128 bytes

void FUN_80039270(undefined4 param_1,undefined *param_2,undefined4 param_3)

{
  int iVar1;
  
  iVar1 = FUN_8000b578(param_1,0x10);
  if (iVar1 == 0) {
    FUN_8000bab0(param_1,0x10,param_3);
    *(float *)(param_2 + 0xc) = FLOAT_803de9c8;
    *(undefined2 *)(param_2 + 0x14) = 0xfb00;
    *param_2 = 1;
    *(float *)(param_2 + 4) = FLOAT_803de99c;
  }
  return;
}

