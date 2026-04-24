// Function: FUN_8012c558
// Entry: 8012c558
// Size: 340 bytes

void FUN_8012c558(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  iVar3 = FUN_8002b9ec();
  iVar8 = 0;
  piVar7 = &DAT_803a9410;
  puVar6 = &DAT_8031bf90;
  do {
    if ((iVar8 < 4) && (*piVar7 == 0)) {
      uVar4 = FUN_8002bdf4(0x20,*puVar6);
      iVar5 = FUN_8002df90(uVar4,4,0xffffffff,0xffffffff,0);
      *piVar7 = iVar5;
      fVar1 = FLOAT_803e1e3c;
      *(float *)(*piVar7 + 0xc) = FLOAT_803e1e3c;
      fVar2 = FLOAT_803e1e5c;
      *(float *)(*piVar7 + 0x10) = FLOAT_803e1e5c;
      *(float *)(*piVar7 + 0x14) = fVar2;
      *(undefined2 *)*piVar7 = 0x7447;
      *(float *)(*piVar7 + 8) = fVar1;
      if (0x90000000 < *(uint *)(*piVar7 + 0x4c)) {
        *(undefined4 *)(*piVar7 + 0x4c) = 0;
      }
    }
    piVar7 = piVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 6);
  DAT_803dd786 = 0;
  DAT_803dd784 = 0;
  DAT_803dd78c = 0;
  FUN_80014b18(0xf);
  if (iVar3 != 0) {
    uVar4 = FUN_8002b9ec();
    FUN_8002ac30(uVar4,0,0,0,0,0);
  }
  FUN_8000a518(0x23,1);
  FUN_8000bb18(0,0x3e5);
  FUN_8000bb18(0,0xff);
  return;
}

