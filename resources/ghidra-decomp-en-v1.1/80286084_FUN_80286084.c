// Function: FUN_80286084
// Entry: 80286084
// Size: 172 bytes

uint FUN_80286084(byte *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  byte local_20 [12];
  
  uVar2 = DAT_cc006828;
  DAT_cc006828 = uVar2 & 0x405 | 0xc0;
  local_20[0] = 0x40;
  local_20[1] = 0;
  local_20[2] = 0;
  local_20[3] = 0;
  uVar4 = FUN_80285b88(local_20,2,1);
  uVar2 = countLeadingZeros(uVar4);
  do {
    uVar3 = DAT_cc006834;
  } while ((uVar3 & 1) != 0);
  uVar4 = FUN_80285b88(param_1,4,0);
  uVar3 = countLeadingZeros(uVar4);
  do {
    uVar1 = DAT_cc006834;
  } while ((uVar1 & 1) != 0);
  uVar1 = DAT_cc006828;
  uVar2 = countLeadingZeros((uVar2 | uVar3) >> 5);
  DAT_cc006828 = uVar1 & 0x405;
  return uVar2 >> 5;
}

