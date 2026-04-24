// Function: FUN_80204b24
// Entry: 80204b24
// Size: 92 bytes

undefined4 FUN_80204b24(int param_1)

{
  short sVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar2 = FUN_8002bac4();
  sVar1 = *psVar3;
  if (0 < sVar1) {
    *psVar3 = sVar1 - (short)(int)FLOAT_803dc074;
    FUN_80296848(iVar2,0x51e);
  }
  return 0;
}

