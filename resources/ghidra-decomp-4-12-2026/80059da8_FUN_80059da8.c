// Function: FUN_80059da8
// Entry: 80059da8
// Size: 132 bytes

void FUN_80059da8(undefined *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar1 = (int)DAT_803dda6c;
    piVar3 = &DAT_80382eac;
    if (0 < iVar1) {
      do {
        if ((*piVar3 != 0) && (iVar4 == *(short *)(piVar3 + 1))) goto LAB_80059dfc;
        piVar3 = piVar3 + 2;
        iVar2 = iVar2 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar2 = -1;
LAB_80059dfc:
    if (iVar2 == -1) {
      *param_1 = 0;
    }
    else {
      *param_1 = 1;
    }
    iVar4 = iVar4 + 1;
    param_1 = param_1 + 1;
    if (0x77 < iVar4) {
      return;
    }
  } while( true );
}

