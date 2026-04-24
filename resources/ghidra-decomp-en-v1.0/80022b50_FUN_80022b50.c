// Function: FUN_80022b50
// Entry: 80022b50
// Size: 464 bytes

int FUN_80022b50(int param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = 0;
  if (param_1 < 1) {
    FUN_8007d6dc(s__mmCreateMemoryStore__failed_as_s_802ca7d8,param_1);
  }
  else if (param_1 < 0x4001) {
    piVar1 = (int *)FUN_80023cc8(0x10,0,s_mmStore_803db438);
    if (piVar1 == (int *)0x0) {
      FUN_8007d6dc(s__mmCreateMemoryStore__failed_to_a_802ca85c);
    }
    else {
      piVar1[2] = param_1;
      iVar2 = DAT_803dcb38 + 1;
      piVar1[3] = DAT_803dcb38;
      DAT_803dcb38 = iVar2;
      *piVar1 = 0;
      piVar1[1] = 0;
      iVar2 = FUN_80023cc8(piVar1[2],0,s_mmStore__ptrStore_802ca898);
      *piVar1 = iVar2;
      if (*piVar1 == 0) {
        FUN_8007d6dc(s__mmCreateMemoryStore__failed_to_a_802ca8ac);
        if (DAT_803dcb3c == 0) {
          FUN_800233e8(piVar1);
        }
        else {
          FUN_8002330c(piVar1);
        }
      }
      else {
        piVar1[1] = *piVar1;
        piVar3 = &DAT_8033c7a0;
        do {
          if (0x1f < iVar4) {
LAB_80022cfc:
            return piVar1[3];
          }
          if (*piVar3 == 0) {
            (&DAT_8033c7a0)[iVar4] = piVar1;
            goto LAB_80022cfc;
          }
          piVar3 = piVar3 + 1;
          iVar4 = iVar4 + 1;
        } while (iVar4 != 0x20);
        FUN_8007d6dc(s__mmCreateMemoryStore__failed_to_f_802ca8e8);
        if (DAT_803dcb3c == 0) {
          FUN_800233e8();
        }
        else {
          FUN_8002330c(*piVar1);
        }
        if (DAT_803dcb3c == 0) {
          FUN_800233e8(piVar1);
        }
        else {
          FUN_8002330c(piVar1);
        }
      }
    }
  }
  else {
    FUN_8007d6dc(s__mmCreateMemoryStore__failed_as_s_802ca808,param_1,0x4000);
  }
  return 0;
}

