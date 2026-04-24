// Function: FUN_802044ec
// Entry: 802044ec
// Size: 92 bytes

undefined4 FUN_802044ec(int param_1)

{
  short sVar1;
  undefined4 uVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  uVar2 = FUN_8002b9ec();
  sVar1 = *psVar3;
  if (0 < sVar1) {
    *psVar3 = sVar1 - (short)(int)FLOAT_803db414;
    FUN_802960e8(uVar2,0x51e);
  }
  return 0;
}

