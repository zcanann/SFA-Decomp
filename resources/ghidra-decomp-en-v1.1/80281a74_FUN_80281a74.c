// Function: FUN_80281a74
// Entry: 80281a74
// Size: 40 bytes

void FUN_80281a74(uint param_1,uint param_2,uint param_3)

{
  (&DAT_803d4900)[(param_2 & 0xff) * 0x10 + (param_1 & 0xff)] =
       (&DAT_803d4900)[(param_2 & 0xff) * 0x10 + (param_1 & 0xff)] | param_3;
  return;
}

