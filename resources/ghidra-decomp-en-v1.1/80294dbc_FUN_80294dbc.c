// Function: FUN_80294dbc
// Entry: 80294dbc
// Size: 40 bytes

uint FUN_80294dbc(uint param_1)

{
  if (param_1 == 0xffffffff) {
    return 0xffffffff;
  }
  return (uint)(byte)(&DAT_80333348)[param_1 & 0xff];
}

