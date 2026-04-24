// Function: FUN_8001b46c
// Entry: 8001b46c
// Size: 536 bytes

void FUN_8001b46c(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int *piVar5;
  undefined4 unaff_r31;
  int local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  if (DAT_803dca04 == 2) {
    if (DAT_803dc9f0 != 0) {
      unaff_r31 = FUN_80019b14();
      FUN_80019b1c(1,2);
    }
    iVar2 = FUN_8002073c();
    if (iVar2 == 0) {
      DAT_803dca10 = DAT_803dca10 + DAT_803db410;
    }
    uStack28 = DAT_803dca10 ^ 0x80000000;
    local_20 = 0x43300000;
    FLOAT_803dca0c =
         (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de728) / FLOAT_803de720;
    if ((DAT_803dca08 + 1 < DAT_803dca18) &&
       ((float)(&DAT_8033ba44)[DAT_803dca08] <= FLOAT_803dca0c)) {
      iVar2 = FUN_80018bc4((&DAT_8033b640)[DAT_803dca08],local_28);
      if (iVar2 != 0) {
        piVar5 = (int *)(iVar2 + local_28[0] * 0xc);
        do {
          piVar5 = piVar5 + -3;
          iVar1 = local_28[0] + -1;
          if (local_28[0] == 0) goto LAB_8001b5c0;
          local_28[0] = iVar1;
        } while (*piVar5 != 0xf8ff);
        iVar3 = iVar2 + iVar1 * 0xc;
        DAT_803dc9f7 = (undefined)*(undefined2 *)(iVar3 + 4);
        DAT_803dc9f6 = (undefined)*(undefined2 *)(iVar3 + 6);
        DAT_803dc9f5 = (undefined)*(undefined2 *)(iVar3 + 8);
        DAT_803dc9f4 = (undefined)*(undefined2 *)(iVar3 + 10);
LAB_8001b5c0:
        local_28[0] = iVar1;
        uVar4 = FUN_80023834(0);
        FUN_80023800(iVar2);
        FUN_80023834(uVar4);
      }
      iVar2 = DAT_803dca08 + 1;
      iVar1 = DAT_803dca08 + 2;
      DAT_803dca08 = iVar2;
      if (DAT_803dca18 <= iVar1) {
        FUN_8001b700();
        if (DAT_803dc9f0 == 0) {
          return;
        }
        FUN_80019b1c(unaff_r31,2);
        return;
      }
    }
    FUN_80019908(DAT_803dc9f7,DAT_803dc9f6,DAT_803dc9f5,DAT_803dc9f4);
    FUN_80015dc8((&DAT_8033b640)[DAT_803dca08],10,0,0);
    if (DAT_803dc9f0 != 0) {
      FUN_80019b1c(unaff_r31,2);
    }
  }
  return;
}

