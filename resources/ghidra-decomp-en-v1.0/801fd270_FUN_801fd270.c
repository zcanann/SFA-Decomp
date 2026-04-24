// Function: FUN_801fd270
// Entry: 801fd270
// Size: 264 bytes

void FUN_801fd270(int param_1)

{
  int iVar1;
  short sVar3;
  short sVar4;
  int iVar2;
  short *psVar5;
  double dVar6;
  
  psVar5 = *(short **)(param_1 + 0xb8);
  sVar3 = 1;
  iVar1 = FUN_8002b9ec();
  if (iVar1 != 0) {
    if (psVar5[1] != -1) {
      sVar3 = FUN_8001ffb4();
    }
    sVar4 = FUN_8001ffb4((int)*psVar5);
    if (((sVar4 == 0) && (*(char *)(psVar5 + 2) == '\0')) && (sVar3 != 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      iVar2 = (**(code **)(*DAT_803dca68 + 0x20))(DAT_803ddcc8);
      if ((iVar2 != 0) &&
         (dVar6 = (double)FUN_80021704(param_1 + 0x18,iVar1 + 0x18), dVar6 < (double)FLOAT_803e6150)
         ) {
        FUN_800200e8((int)*psVar5,1);
        *(undefined *)(psVar5 + 2) = 1;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
  }
  return;
}

