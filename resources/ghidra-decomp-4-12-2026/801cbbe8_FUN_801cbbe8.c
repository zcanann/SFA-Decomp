// Function: FUN_801cbbe8
// Entry: 801cbbe8
// Size: 364 bytes

void FUN_801cbbe8(undefined2 *param_1,int param_2)

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
  *(code **)(param_1 + 0x5e) = FUN_801caf74;
  FUN_80037a5c((int)param_1,4);
  FUN_800201ac(0x129,1);
  FUN_800201ac(0x1cf,0);
  FUN_800201ac(0x126,1);
  FUN_800201ac(0x127,1);
  FUN_800201ac(0x1cd,0);
  FUN_800201ac(0x1e7,0);
  psVar3[2] = 0xc;
  psVar3[4] = 0x1e;
  psVar3[1] = 200;
  (**(code **)(*DAT_803dd6f0 + 0x18))(2,0x2b,0x50,1,0);
  psVar3[3] = 0;
  psVar3[5] = 0;
  *(undefined *)(psVar3 + 9) = 0;
  piVar1 = (int *)FUN_80013ee8(0x6a);
  sVar2 = (**(code **)(*piVar1 + 4))(param_1,0,0,0x402,0xffffffff,0);
  psVar3[6] = sVar2;
  FUN_80013e4c((undefined *)piVar1);
  return;
}

