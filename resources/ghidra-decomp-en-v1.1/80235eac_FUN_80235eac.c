// Function: FUN_80235eac
// Entry: 80235eac
// Size: 276 bytes

void FUN_80235eac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  double dVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int *piVar7;
  int *piVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  piVar5 = (int *)uVar9;
  if (*(int *)(iVar2 + 0xf8) != 0) {
    iVar6 = 0;
    piVar7 = piVar5;
    piVar8 = piVar5;
    do {
      if (*piVar8 == 0) {
        piVar8[0xc] = (int)((float)piVar8[0xc] - FLOAT_803dc074);
        if ((float)piVar8[0xc] <= FLOAT_803e7f90) {
          uVar3 = FUN_80022264(0x3c,300);
          dVar1 = DOUBLE_803e7f98;
          piVar8[0xc] = (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                    DOUBLE_803e7f98);
          FUN_80235d90(dVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,piVar5,
                       (char)iVar6,in_r6,in_r7,in_r8,in_r9,in_r10);
        }
      }
      else {
        iVar4 = (**(code **)(**(int **)(*piVar8 + 0x68) + 0x28))();
        if (iVar4 < 4) {
          (**(code **)(**(int **)(*piVar8 + 0x68) + 0x24))(*piVar8,piVar7 + 3);
        }
        else {
          *piVar8 = 0;
        }
      }
      piVar8 = piVar8 + 1;
      piVar7 = piVar7 + 3;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 3);
  }
  FUN_8028688c();
  return;
}

