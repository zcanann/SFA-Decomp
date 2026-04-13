// Function: FUN_8000f584
// Entry: 8000f584
// Size: 540 bytes

void FUN_8000f584(void)

{
  uint uVar1;
  char cVar2;
  ushort local_68;
  short local_66;
  short local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float afStack_50 [18];
  
  uVar1 = (uint)DAT_803dd50d;
  local_5c = -((float)(&DAT_80338e3c)[uVar1 * 0x18] - FLOAT_803dda58);
  local_58 = -(float)(&DAT_80338e40)[uVar1 * 0x18];
  local_54 = -((float)(&DAT_80338e44)[uVar1 * 0x18] - FLOAT_803dda5c);
  local_68 = (&DAT_80338e30)[uVar1 * 0x30] + 0x8000;
  local_66 = (&DAT_80338e32)[uVar1 * 0x30];
  local_64 = (&DAT_80338e34)[uVar1 * 0x30];
  local_60 = FLOAT_803df270;
  cVar2 = FUN_8011f628();
  if (cVar2 == '\0') {
    if (DAT_803dd50c != '\0') {
      local_58 = local_58 - (float)(&DAT_80338e5c)[uVar1 * 0x18];
    }
    local_5c = local_5c + FLOAT_803df28c;
    local_58 = local_58 + FLOAT_803df28c;
    local_54 = local_54 + FLOAT_803df28c;
  }
  FUN_80021c64(afStack_50,(int)&local_68);
  FUN_800216cc(afStack_50,(undefined4 *)&DAT_80339330);
  local_5c = (float)(&DAT_80338e3c)[uVar1 * 0x18] - FLOAT_803dda58;
  local_58 = (float)(&DAT_80338e40)[uVar1 * 0x18];
  local_54 = (float)(&DAT_80338e44)[uVar1 * 0x18] - FLOAT_803dda5c;
  local_68 = -((&DAT_80338e30)[uVar1 * 0x30] + -0x8000);
  local_66 = -(&DAT_80338e32)[uVar1 * 0x30];
  local_64 = -(&DAT_80338e34)[uVar1 * 0x30];
  local_60 = FLOAT_803df270;
  cVar2 = FUN_8011f628();
  if (cVar2 == '\0') {
    if (DAT_803dd50c != '\0') {
      local_58 = local_58 + (float)(&DAT_80338e5c)[uVar1 * 0x18];
    }
    local_5c = local_5c - FLOAT_803df28c;
    local_58 = local_58 - FLOAT_803df28c;
    local_54 = local_54 - FLOAT_803df28c;
  }
  FUN_80021fac((float *)&DAT_80338cf0,&local_68);
  FUN_800216cc((undefined4 *)&DAT_80338cf0,(undefined4 *)&DAT_80339370);
  FUN_802475e4((float *)&DAT_80339330,(float *)&DAT_803392b0);
  DAT_803392bc = FLOAT_803df28c;
  DAT_803392cc = FLOAT_803df28c;
  DAT_803392dc = FLOAT_803df28c;
  FUN_802475e4((float *)&DAT_80339370,(float *)&DAT_803392f0);
  DAT_803392fc = FLOAT_803df28c;
  DAT_8033930c = FLOAT_803df28c;
  DAT_8033931c = FLOAT_803df28c;
  return;
}

