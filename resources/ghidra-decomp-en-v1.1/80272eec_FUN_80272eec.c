// Function: FUN_80272eec
// Entry: 80272eec
// Size: 32 bytes

undefined2 FUN_80272eec(uint param_1,uint param_2)

{
  return (&DAT_803bd8f0)[(param_1 & 0xff) * 0x10 + (param_2 & 0xff)];
}

