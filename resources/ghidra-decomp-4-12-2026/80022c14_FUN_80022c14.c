// Function: FUN_80022c14
// Entry: 80022c14
// Size: 464 bytes

uint FUN_80022c14(uint param_1)

{
  uint *puVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = 0;
  if ((int)param_1 < 1) {
    FUN_8007d858();
  }
  else if ((int)param_1 < 0x4001) {
    puVar1 = (uint *)FUN_80023d8c(0x10,0);
    if (puVar1 == (uint *)0x0) {
      FUN_8007d858();
    }
    else {
      puVar1[2] = param_1;
      uVar2 = DAT_803dd7b8 + 1;
      puVar1[3] = DAT_803dd7b8;
      DAT_803dd7b8 = uVar2;
      *puVar1 = 0;
      puVar1[1] = 0;
      uVar2 = FUN_80023d8c(puVar1[2],0);
      *puVar1 = uVar2;
      if (*puVar1 == 0) {
        FUN_8007d858();
        if (DAT_803dd7bc == 0) {
          FUN_800234ac((uint)puVar1);
        }
        else {
          FUN_800233d0(puVar1);
        }
      }
      else {
        puVar1[1] = *puVar1;
        piVar3 = &DAT_8033d400;
        do {
          if (0x1f < iVar4) {
LAB_80022dc0:
            return puVar1[3];
          }
          if (*piVar3 == 0) {
            (&DAT_8033d400)[iVar4] = puVar1;
            goto LAB_80022dc0;
          }
          piVar3 = piVar3 + 1;
          iVar4 = iVar4 + 1;
        } while (iVar4 != 0x20);
        FUN_8007d858();
        if (DAT_803dd7bc == 0) {
          FUN_800234ac(*puVar1);
        }
        else {
          FUN_800233d0(*puVar1);
        }
        if (DAT_803dd7bc == 0) {
          FUN_800234ac((uint)puVar1);
        }
        else {
          FUN_800233d0(puVar1);
        }
      }
    }
  }
  else {
    FUN_8007d858();
  }
  return 0;
}

