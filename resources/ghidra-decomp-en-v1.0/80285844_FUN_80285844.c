// Function: FUN_80285844
// Entry: 80285844
// Size: 220 bytes

uint FUN_80285844(uint param_1,undefined4 *param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 local_20;
  uint local_1c;
  
  local_1c = (param_1 & 0x1fffc) << 8 | 0xa0000000;
  uVar1 = read_volatile_4(DAT_cc006828);
  write_volatile_4(DAT_cc006828,uVar1 & 0x405 | 0xc0);
  uVar3 = FUN_80285424(&local_1c,4,1);
  uVar1 = countLeadingZeros(uVar3);
  uVar1 = uVar1 >> 5;
  do {
    uVar2 = read_volatile_4(DAT_cc006834);
  } while ((uVar2 & 1) != 0);
  while (param_3 != 0) {
    local_20 = *param_2;
    param_2 = param_2 + 1;
    uVar3 = FUN_80285424(&local_20,4,1);
    uVar2 = countLeadingZeros(uVar3);
    uVar1 = uVar1 | uVar2 >> 5;
    do {
      uVar2 = read_volatile_4(DAT_cc006834);
    } while ((uVar2 & 1) != 0);
    param_3 = param_3 + -4;
    if (param_3 < 0) {
      param_3 = 0;
    }
  }
  uVar2 = read_volatile_4(DAT_cc006828);
  uVar1 = countLeadingZeros(uVar1);
  write_volatile_4(DAT_cc006828,uVar2 & 0x405);
  return uVar1 >> 5;
}

