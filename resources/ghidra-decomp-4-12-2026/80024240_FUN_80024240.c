// Function: FUN_80024240
// Entry: 80024240
// Size: 400 bytes

undefined4 * FUN_80024240(int param_1,int param_2)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  int *piVar6;
  int iVar7;
  uint uVar8;
  
  uVar2 = FUN_80022de4(2);
  puVar3 = (undefined4 *)FUN_80023d8c(param_2 * param_1 + 0x20,0x11);
  FUN_80022de4(uVar2);
  *(short *)(puVar3 + 3) = (short)param_2;
  *(short *)((int)puVar3 + 0xe) = (short)param_1;
  *(undefined2 *)(puVar3 + 4) = 0;
  puVar3[1] = (int)puVar3 + (int)*(short *)((int)puVar3 + 0xe) * (int)*(short *)(puVar3 + 3) + 0x20;
  piVar6 = puVar3 + 8;
  iVar7 = (int)piVar6 + param_2;
  uVar4 = param_1 - 2;
  piVar5 = piVar6;
  if (0 < (int)uVar4) {
    uVar8 = uVar4 >> 3;
    if (uVar8 != 0) {
      do {
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        *piVar5 = iVar7 + param_2;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2 + param_2;
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2;
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2;
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2;
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2;
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2;
        *piVar5 = iVar7;
        piVar5 = (int *)*piVar5;
        iVar7 = iVar7 + param_2;
        uVar8 = uVar8 - 1;
      } while (uVar8 != 0);
      uVar4 = uVar4 & 7;
      if (uVar4 == 0) goto LAB_80024368;
    }
    do {
      *piVar5 = iVar7;
      piVar5 = (int *)*piVar5;
      iVar7 = iVar7 + param_2;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
LAB_80024368:
  *piVar5 = 0;
  *puVar3 = piVar6;
  piVar5 = (int *)*puVar3;
  while( true ) {
    if (piVar5 == (int *)0x0) {
      return puVar3;
    }
    bVar1 = false;
    if ((piVar6 <= piVar5) && (piVar5 < (int *)puVar3[1])) {
      bVar1 = true;
    }
    if (!bVar1) break;
    piVar5 = (int *)*piVar5;
  }
  return puVar3;
}

