// Function: FUN_80207c34
// Entry: 80207c34
// Size: 168 bytes

void FUN_80207c34(undefined4 param_1,int param_2)

{
  short sVar1;
  int *piVar2;
  
  if (param_2 == 0) {
    piVar2 = &DAT_803ad138;
    for (sVar1 = 0; sVar1 < 4; sVar1 = sVar1 + 1) {
      if (*piVar2 != 0) {
        FUN_8002cbc4();
      }
      *piVar2 = 0;
      if (piVar2[1] != 0) {
        FUN_8002cbc4();
      }
      piVar2[1] = 0;
      FUN_8000bb18(param_1,0x1ce);
      piVar2 = piVar2 + 2;
    }
  }
  FUN_8001467c();
  return;
}

