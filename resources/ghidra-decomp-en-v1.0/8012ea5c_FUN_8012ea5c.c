// Function: FUN_8012ea5c
// Entry: 8012ea5c
// Size: 172 bytes

void FUN_8012ea5c(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  if ((param_1 != -1) && (DAT_803dba70 == -1)) {
    FUN_800173c8(0x7c);
    DAT_803dd7a8 = 1;
    DAT_803dd8d0 = 0;
    DAT_803dba70 = (short)param_1;
    DAT_803dd8ca = 0xffff;
    DAT_803dd8c8 = 1;
    FUN_80016c48(&DAT_803a9440);
    if (param_4 == 0) {
      DAT_803dd7a9 = 0;
    }
    else {
      FUN_800206e8(1);
      FUN_80020628(0xff);
      DAT_803dd7a9 = 1;
    }
  }
  return;
}

