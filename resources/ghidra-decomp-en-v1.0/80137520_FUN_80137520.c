// Function: FUN_80137520
// Entry: 80137520
// Size: 128 bytes

void FUN_80137520(undefined param_1,undefined param_2,undefined param_3,undefined param_4)

{
  undefined *puVar1;
  
  DAT_803dd9e4 = DAT_803dd9e4 + 1;
  if (0xfa < DAT_803dd9e4) {
    return;
  }
  puVar1 = DAT_803dbc14 + 1;
  *DAT_803dbc14 = 0x81;
  DAT_803dbc14 = puVar1;
  puVar1 = DAT_803dbc14 + 1;
  *DAT_803dbc14 = param_1;
  DAT_803dbc14 = puVar1;
  puVar1 = DAT_803dbc14 + 1;
  *DAT_803dbc14 = param_2;
  DAT_803dbc14 = puVar1;
  puVar1 = DAT_803dbc14 + 1;
  *DAT_803dbc14 = param_3;
  DAT_803dbc14 = puVar1;
  puVar1 = DAT_803dbc14 + 1;
  *DAT_803dbc14 = param_4;
  DAT_803dbc14 = puVar1;
  puVar1 = DAT_803dbc14 + 1;
  *DAT_803dbc14 = 0;
  DAT_803dbc14 = puVar1;
  return;
}

