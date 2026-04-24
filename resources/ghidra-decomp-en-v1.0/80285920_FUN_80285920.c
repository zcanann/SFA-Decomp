// Function: FUN_80285920
// Entry: 80285920
// Size: 172 bytes

uint FUN_80285920(undefined4 param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 local_20 [3];
  
  uVar2 = read_volatile_4(DAT_cc006828);
  write_volatile_4(DAT_cc006828,uVar2 & 0x405 | 0xc0);
  local_20[0] = 0x40000000;
  uVar4 = FUN_80285424(local_20,2,1);
  uVar2 = countLeadingZeros(uVar4);
  do {
    uVar3 = read_volatile_4(DAT_cc006834);
  } while ((uVar3 & 1) != 0);
  uVar4 = FUN_80285424(param_1,4,0);
  uVar3 = countLeadingZeros(uVar4);
  do {
    uVar1 = read_volatile_4(DAT_cc006834);
  } while ((uVar1 & 1) != 0);
  uVar1 = read_volatile_4(DAT_cc006828);
  uVar2 = countLeadingZeros((uVar2 | uVar3) >> 5);
  write_volatile_4(DAT_cc006828,uVar1 & 0x405);
  return uVar2 >> 5;
}

