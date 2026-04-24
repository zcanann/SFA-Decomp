// Function: FUN_802357e8
// Entry: 802357e8
// Size: 276 bytes

void FUN_802357e8(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  piVar4 = (int *)uVar8;
  if (*(int *)(iVar1 + 0xf8) != 0) {
    iVar5 = 0;
    piVar6 = piVar4;
    piVar7 = piVar4;
    do {
      if (*piVar7 == 0) {
        piVar7[0xc] = (int)((float)piVar7[0xc] - FLOAT_803db414);
        if ((float)piVar7[0xc] <= FLOAT_803e72f8) {
          uVar2 = FUN_800221a0(0x3c,300);
          piVar7[0xc] = (int)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                    DOUBLE_803e7300);
          FUN_802356cc(iVar1,piVar4,(int)(char)iVar5);
        }
      }
      else {
        iVar3 = (**(code **)(**(int **)(*piVar7 + 0x68) + 0x28))();
        if (iVar3 < 4) {
          (**(code **)(**(int **)(*piVar7 + 0x68) + 0x24))(*piVar7,piVar6 + 3);
        }
        else {
          *piVar7 = 0;
        }
      }
      piVar7 = piVar7 + 1;
      piVar6 = piVar6 + 3;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
  }
  FUN_80286128();
  return;
}

