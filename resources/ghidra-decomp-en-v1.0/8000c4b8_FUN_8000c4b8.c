// Function: FUN_8000c4b8
// Entry: 8000c4b8
// Size: 520 bytes

void FUN_8000c4b8(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  float fVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  
  uVar7 = FUN_802860dc();
  uVar8 = FUN_8000a188(4);
  iVar4 = (int)uVar8;
  if ((int)((ulonglong)uVar8 >> 0x20) == 0) {
    piVar5 = &DAT_80336000;
    iVar4 = 0x37;
    iVar6 = 7;
    do {
      piVar3 = piVar5;
      if (((((*piVar5 == -1) || (piVar3 = piVar5 + 0xe, *piVar3 == -1)) ||
           (piVar3 = piVar5 + 0x1c, *piVar3 == -1)) ||
          ((piVar3 = piVar5 + 0x2a, *piVar3 == -1 || (piVar3 = piVar5 + 0x38, *piVar3 == -1)))) ||
         ((piVar3 = piVar5 + 0x46, *piVar3 == -1 ||
          ((piVar3 = piVar5 + 0x54, *piVar3 == -1 || (piVar3 = piVar5 + 0x62, piVar5[0x62] == -1))))
         )) goto LAB_8000c5d4;
      piVar5 = piVar5 + 0x70;
      iVar4 = iVar4 + -7;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    piVar3 = (int *)0x0;
LAB_8000c5d4:
    if (piVar3 == (int *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      uVar8 = FUN_802728a8((int)((ulonglong)uVar7 >> 0x20),(int)uVar7,param_3,0);
      iVar6 = (int)((ulonglong)uVar8 >> 0x20);
      iVar4 = (int)uVar8;
      if (iVar6 == -1) {
        *piVar3 = -1;
        piVar3 = (int *)0x0;
      }
      else {
        if ((DAT_803dc838 != '\0') && (param_4 == 0)) {
          FUN_802727a8(iVar6,0x5b);
        }
        piVar3[6] = 0;
        *(undefined2 *)(piVar3 + 7) = 0;
        *(undefined *)((int)piVar3 + 6) = 0;
        *(undefined *)(piVar3 + 1) = 0;
        *(undefined *)((int)piVar3 + 5) = 0;
        *piVar3 = iVar6;
        fVar1 = FLOAT_803de570;
        piVar3[3] = (int)FLOAT_803de570;
        piVar3[4] = (int)fVar1;
        piVar3[5] = (int)fVar1;
        *(short *)(piVar3 + 2) = (short)((ulonglong)uVar7 >> 0x20);
        *(undefined *)((int)piVar3 + 7) = 100;
        piVar3[8] = (int)FLOAT_803de590;
        piVar3[9] = (int)FLOAT_803de594;
        *(char *)(piVar3 + 10) = (char)param_4;
        iVar4 = DAT_803dc840;
        DAT_803dc840 = DAT_803dc840 + (uint)(0xfffffffe < DAT_803dc844);
        uVar2 = DAT_803dc844 + 1;
        piVar3[0xd] = DAT_803dc844;
        DAT_803dc844 = uVar2;
        piVar3[0xc] = iVar4;
      }
    }
  }
  else {
    piVar3 = (int *)0x0;
  }
  FUN_80286128(piVar3,iVar4);
  return;
}

