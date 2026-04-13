// Function: FUN_8000a284
// Entry: 8000a284
// Size: 128 bytes

void FUN_8000a284(int param_1,int *param_2)

{
  if (param_1 == -1) {
    FUN_8007d858();
    FUN_802493c8(param_2);
    FUN_800238c4((uint)param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800238c4((uint)param_2);
    DAT_803dd478 = DAT_803dd478 & 0xfffff7ff;
    DAT_803dd474 = DAT_803dd474 | 0x800;
  }
  return;
}

