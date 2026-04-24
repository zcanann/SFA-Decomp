// Function: FUN_80125d8c
// Entry: 80125d8c
// Size: 280 bytes

void FUN_80125d8c(void)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  int *piVar5;
  int iVar6;
  
  iVar6 = 0;
  piVar5 = &DAT_803a93f8;
  puVar4 = &DAT_8031bf90;
  do {
    if (((iVar6 == 3) || (iVar6 == 2)) || (iVar6 == 1)) {
      if (*piVar5 == 0) {
        uVar2 = FUN_8002bdf4(0x20,*puVar4);
        iVar3 = FUN_8002df90(uVar2,4,0xffffffff,0xffffffff,0);
        *piVar5 = iVar3;
        fVar1 = FLOAT_803e1e3c;
        *(float *)(*piVar5 + 0xc) = FLOAT_803e1e3c;
        *(float *)(*piVar5 + 0x10) = fVar1;
        *(float *)(*piVar5 + 0x14) = FLOAT_803e1e5c;
        *(undefined2 *)*piVar5 = 0x7447;
        *(float *)(*piVar5 + 8) = FLOAT_803e205c;
        if (0x90000000 < *(uint *)(*piVar5 + 0x4c)) {
          *(undefined4 *)(*piVar5 + 0x4c) = 0;
        }
        FUN_80030334((double)FLOAT_803e1e3c,*piVar5,1,0);
      }
    }
    else {
      *piVar5 = 0;
    }
    piVar5 = piVar5 + 1;
    puVar4 = puVar4 + 1;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 6);
  return;
}

