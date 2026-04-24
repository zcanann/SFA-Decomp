// Function: FUN_80221744
// Entry: 80221744
// Size: 488 bytes

void FUN_80221744(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int *piVar6;
  double dVar7;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  iVar3 = FUN_8002b9ec();
  iVar4 = FUN_8001ffb4(0xadb);
  if ((iVar4 == 0) &&
     (dVar7 = (double)FUN_80021704(param_1 + 0x18,iVar3 + 0x18), dVar7 < (double)FLOAT_803e6c24)) {
    (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    FUN_800200e8(0xadb,1);
  }
  iVar3 = FUN_80080150(piVar6 + 2);
  if (iVar3 != 0) {
    if (((float)piVar6[2] <= FLOAT_803e6c28) && (*(char *)(piVar6 + 1) == '\0')) {
      *(undefined *)(piVar6 + 1) = 1;
      FUN_80030334((double)FLOAT_803e6c2c,param_1,0,0);
      FUN_8000bb18(param_1,0x328);
      *(undefined *)(piVar6 + 3) = 0;
    }
    iVar3 = FUN_800801a8(piVar6 + 2);
    if ((iVar3 != 0) && (iVar3 = FUN_800379dc(*piVar6), iVar3 != 0)) {
      iVar3 = *piVar6;
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(param_1 + 0x14);
      *(undefined4 *)(iVar3 + 0x80) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(iVar3 + 0x84) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(iVar3 + 0x88) = *(undefined4 *)(iVar3 + 0x14);
      *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(iVar3 + 0x1c) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(iVar3 + 0x14);
      fVar1 = FLOAT_803e6c2c;
      *(float *)(iVar3 + 0x2c) = FLOAT_803e6c2c;
      *(float *)(iVar3 + 0x28) = fVar1;
      *(float *)(iVar3 + 0x24) = fVar1;
      FUN_80037200(*piVar6,0x19);
      *piVar6 = 0;
    }
  }
  if (*(char *)(piVar6 + 1) != '\0') {
    if ((FLOAT_803e6c30 < *(float *)(param_1 + 0x98)) && (*(char *)(piVar6 + 3) == '\0')) {
      FUN_8000bb18(param_1,0x329);
      *(undefined *)(piVar6 + 3) = 1;
    }
    uVar5 = FUN_8002fa48((double)FLOAT_803e6c34,(double)FLOAT_803db414,param_1,0);
    uVar2 = countLeadingZeros(uVar5);
    *(char *)(piVar6 + 1) = (char)(uVar2 >> 5);
  }
  return;
}

