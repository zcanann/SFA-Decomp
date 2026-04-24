// Function: FUN_8026f53c
// Entry: 8026f53c
// Size: 72 bytes

void FUN_8026f53c(int param_1,byte param_2,uint param_3)

{
  if (param_2 == 0xff) {
    param_2 = 8;
  }
  *(uint *)(&DAT_803bcd90 + (param_3 & 0xff) * 4 + (uint)param_2 * 0x40) =
       (uint)(param_1 * 0x3000) / 0xf0;
  return;
}

