// Function: FUN_801cb634
// Entry: 801cb634
// Size: 364 bytes

void FUN_801cb634(undefined2 *param_1,int param_2)

{
  int *piVar1;
  short sVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0x5c);
  *param_1 = 0;
  *psVar3 = 10;
  if (0 < *(short *)(param_2 + 0x1a)) {
    *psVar3 = *(short *)(param_2 + 0x1a) >> 8;
  }
  *(undefined *)((int)psVar3 + 0xf) = 0;
  *(undefined *)(psVar3 + 8) = 0;
  psVar3[1] = 0;
  *(undefined *)(psVar3 + 7) = 0;
  *(code **)(param_1 + 0x5e) = FUN_801ca9c0;
  FUN_80037964(param_1,4);
  FUN_800200e8(0x129,1);
  FUN_800200e8(0x1cf,0);
  FUN_800200e8(0x126,1);
  FUN_800200e8(0x127,1);
  FUN_800200e8(0x1cd,0);
  FUN_800200e8(0x1e7,0);
  psVar3[2] = 0xc;
  psVar3[4] = 0x1e;
  psVar3[1] = 200;
  (**(code **)(*DAT_803dca70 + 0x18))(2,0x2b,0x50,1,0);
  psVar3[3] = 0;
  psVar3[5] = 0;
  *(undefined *)(psVar3 + 9) = 0;
  piVar1 = (int *)FUN_80013ec8(0x6a,1);
  sVar2 = (**(code **)(*piVar1 + 4))(param_1,0,0,0x402,0xffffffff,0);
  psVar3[6] = sVar2;
  FUN_80013e2c(piVar1);
  return;
}

