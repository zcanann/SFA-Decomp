// Function: FUN_8027a51c
// Entry: 8027a51c
// Size: 240 bytes

void FUN_8027a51c(uint param_1,uint param_2)

{
  float fVar1;
  uint uVar2;
  
  if (param_2 == 0xffffffff) {
    param_2 = 0x40005622;
  }
  uVar2 = param_2 >> 0x18;
  param_1 = param_1 & 0xff;
  if (param_1 == uVar2) {
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 & 0xffffff) - DOUBLE_803e7820);
  }
  else {
    if (uVar2 < param_1) {
      fVar1 = *(float *)(&DAT_8032f218 + (param_1 - uVar2) * 4);
    }
    else {
      fVar1 = *(float *)(&DAT_8032f418 + (uVar2 - param_1) * 4);
    }
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 & 0xffffff) - DOUBLE_803e7820) * fVar1;
  }
  FUN_80285fb4((double)((FLOAT_803e7828 * fVar1) /
                       (float)((double)CONCAT44(0x43300000,DAT_803bd150) - DOUBLE_803e7820)));
  return;
}

