// Function: FUN_8000f564
// Entry: 8000f564
// Size: 540 bytes

void FUN_8000f564(void)

{
  uint uVar1;
  char cVar2;
  short local_68;
  short local_66;
  short local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined auStack80 [72];
  
  uVar1 = (uint)DAT_803dc88d;
  local_5c = -((float)(&DAT_803381dc)[uVar1 * 0x18] - FLOAT_803dcdd8);
  local_58 = -(float)(&DAT_803381e0)[uVar1 * 0x18];
  local_54 = -((float)(&DAT_803381e4)[uVar1 * 0x18] - FLOAT_803dcddc);
  local_68 = (&DAT_803381d0)[uVar1 * 0x30] + -0x8000;
  local_66 = (&DAT_803381d2)[uVar1 * 0x30];
  local_64 = (&DAT_803381d4)[uVar1 * 0x30];
  local_60 = FLOAT_803de5f0;
  cVar2 = FUN_8011f344();
  if (cVar2 == '\0') {
    if (DAT_803dc88c != '\0') {
      local_58 = local_58 - (float)(&DAT_803381fc)[uVar1 * 0x18];
    }
    local_5c = local_5c + FLOAT_803de60c;
    local_58 = local_58 + FLOAT_803de60c;
    local_54 = local_54 + FLOAT_803de60c;
  }
  FUN_80021ba0(auStack80,&local_68);
  FUN_80021608(auStack80,&DAT_803386d0);
  local_5c = (float)(&DAT_803381dc)[uVar1 * 0x18] - FLOAT_803dcdd8;
  local_58 = (float)(&DAT_803381e0)[uVar1 * 0x18];
  local_54 = (float)(&DAT_803381e4)[uVar1 * 0x18] - FLOAT_803dcddc;
  local_68 = -((&DAT_803381d0)[uVar1 * 0x30] + -0x8000);
  local_66 = -(&DAT_803381d2)[uVar1 * 0x30];
  local_64 = -(&DAT_803381d4)[uVar1 * 0x30];
  local_60 = FLOAT_803de5f0;
  cVar2 = FUN_8011f344();
  if (cVar2 == '\0') {
    if (DAT_803dc88c != '\0') {
      local_58 = local_58 + (float)(&DAT_803381fc)[uVar1 * 0x18];
    }
    local_5c = local_5c - FLOAT_803de60c;
    local_58 = local_58 - FLOAT_803de60c;
    local_54 = local_54 - FLOAT_803de60c;
  }
  FUN_80021ee8(&DAT_80338090,&local_68);
  FUN_80021608(&DAT_80338090,&DAT_80338710);
  FUN_80246e80(&DAT_803386d0,&DAT_80338650);
  DAT_8033865c = FLOAT_803de60c;
  DAT_8033866c = FLOAT_803de60c;
  DAT_8033867c = FLOAT_803de60c;
  FUN_80246e80(&DAT_80338710,&DAT_80338690);
  DAT_8033869c = FLOAT_803de60c;
  DAT_803386ac = FLOAT_803de60c;
  DAT_803386bc = FLOAT_803de60c;
  return;
}

