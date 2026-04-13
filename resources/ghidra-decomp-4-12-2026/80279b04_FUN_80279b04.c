// Function: FUN_80279b04
// Entry: 80279b04
// Size: 252 bytes

uint FUN_80279b04(int param_1,int param_2)

{
  bool bVar1;
  int *piVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  int *piVar7;
  
  piVar2 = DAT_803def78;
  uVar5 = DAT_803def70;
  do {
    DAT_803def70 = uVar5;
    uVar5 = DAT_803def70 + 1;
  } while (DAT_803def70 == 0xffffffff);
  uVar5 = DAT_803def70;
  piVar3 = DAT_803def74;
  piVar7 = (int *)0x0;
  DAT_803def70 = DAT_803def70 + 1;
  while ((piVar6 = piVar3, piVar6 != (int *)0x0 && ((uint)piVar6[2] <= uVar5))) {
    if (piVar6[2] == uVar5) {
      do {
        uVar4 = DAT_803def70 + 1;
        bVar1 = DAT_803def70 == 0xffffffff;
        uVar5 = DAT_803def70;
        DAT_803def70 = uVar4;
      } while (bVar1);
    }
    piVar7 = piVar6;
    piVar3 = (int *)*piVar6;
  }
  if (DAT_803def78 != (int *)0x0) {
    DAT_803def78 = (int *)*DAT_803def78;
    if (DAT_803def78 != (int *)0x0) {
      *(undefined4 *)((int)DAT_803def78 + 4) = 0;
    }
    if (piVar7 == (int *)0x0) {
      DAT_803def74 = piVar2;
    }
    else {
      *piVar7 = (int)piVar2;
    }
    piVar2[1] = (int)piVar7;
    *piVar2 = (int)piVar6;
    if (piVar6 != (int *)0x0) {
      piVar6[1] = (int)piVar2;
    }
    piVar2[2] = uVar5;
    piVar2[3] = *(int *)(param_1 + 0xf4);
    piVar3 = piVar2;
    if (param_2 == 0) {
      piVar3 = (int *)0x0;
    }
    *(int **)(param_1 + 0xfc) = piVar3;
    *(int **)(param_1 + 0xf8) = piVar2;
    if (param_2 == 0) {
      return *(uint *)(param_1 + 0xf4);
    }
    return uVar5;
  }
  return 0xffffffff;
}

