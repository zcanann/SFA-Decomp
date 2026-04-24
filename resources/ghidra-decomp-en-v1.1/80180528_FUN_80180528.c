// Function: FUN_80180528
// Entry: 80180528
// Size: 584 bytes

void FUN_80180528(undefined4 param_1,undefined4 param_2,byte *param_3,int param_4,int param_5)

{
  uint uVar1;
  int iVar2;
  byte bVar7;
  int *piVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar8;
  byte *pbVar9;
  undefined8 uVar10;
  int local_28 [10];
  
  uVar10 = FUN_8028683c();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  pbVar8 = (byte *)uVar10;
  uVar1 = FUN_80020078(0x4e5);
  if ((uVar1 != 0) && (iVar2 = FUN_8002ba84(), iVar2 != 0)) {
    if (*pbVar8 == 0) {
      bVar7 = FUN_800dbf88((float *)(iVar4 + 0xc),(undefined *)0x0);
      *pbVar8 = bVar7;
      if (*pbVar8 == 0) goto LAB_80180758;
      piVar3 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_28);
      param_3 = pbVar8;
      for (param_4 = 0; param_4 < local_28[0]; param_4 = param_4 + 1) {
        iVar2 = *piVar3;
        if ((*(char *)(iVar2 + 0x19) == '$') && (*(char *)(iVar2 + 3) == '\0')) {
          param_5 = 0;
          iVar5 = 4;
          do {
            if (*(byte *)(iVar2 + param_5 + 4) == *pbVar8) {
              *(undefined4 *)(param_3 + 4) = *(undefined4 *)(iVar2 + 0x14);
              param_3 = param_3 + 4;
              break;
            }
            param_5 = param_5 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        piVar3 = piVar3 + 1;
      }
    }
    iVar4 = FUN_8005a288((double)FLOAT_803e4538,(float *)(iVar4 + 0xc));
    if (iVar4 == 0) {
      iVar4 = FUN_8002bac4();
      uVar1 = FUN_800dbf88((float *)(iVar4 + 0xc),(undefined *)0x0);
      bVar7 = (byte)param_5;
      if (uVar1 != 0) {
        if (uVar1 == *pbVar8) goto LAB_80180758;
        iVar2 = 0;
        pbVar9 = pbVar8;
        do {
          bVar7 = (byte)param_5;
          if (*(int *)(pbVar9 + 4) == 0) break;
          iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))();
          if ((((iVar5 != 0) &&
               (((int)*(short *)(iVar5 + 0x30) == 0xffffffff ||
                (uVar6 = FUN_80020078((int)*(short *)(iVar5 + 0x30)), uVar6 != 0)))) &&
              (((int)*(short *)(iVar5 + 0x32) == 0xffffffff ||
               (uVar6 = FUN_80020078((int)*(short *)(iVar5 + 0x32)), uVar6 == 0)))) &&
             ((((*(byte *)(iVar5 + 4) == uVar1 || (*(byte *)(iVar5 + 5) == uVar1)) ||
               (*(byte *)(iVar5 + 6) == uVar1)) || (*(byte *)(iVar5 + 7) == uVar1))))
          goto LAB_80180758;
          bVar7 = (byte)param_5;
          pbVar9 = pbVar9 + 4;
          iVar2 = iVar2 + 1;
        } while (iVar2 < 0x18);
      }
      FUN_800dbcd8((float *)(iVar4 + 0xc),(uint)*pbVar8,param_3,param_4,bVar7);
    }
  }
LAB_80180758:
  FUN_80286888();
  return;
}

