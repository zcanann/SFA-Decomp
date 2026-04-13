// Function: FUN_801e7c90
// Entry: 801e7c90
// Size: 1452 bytes

void FUN_801e7c90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,char param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined2 uVar8;
  int *piVar7;
  float *pfVar9;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  uint uVar13;
  undefined8 extraout_f1;
  undefined8 uVar14;
  double dVar15;
  double extraout_f1_00;
  float local_28 [10];
  
  iVar4 = FUN_80286838();
  iVar1 = *(int *)(iVar4 + 0xb8);
  uVar14 = extraout_f1;
  iVar5 = FUN_8002bac4();
  local_28[0] = FLOAT_803e6670;
  *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) & 0xdf;
  if ((*(byte *)(iVar1 + 0x9d4) & 0x10) == 0) {
    pfVar9 = (float *)(iVar1 + 0x35c);
    iVar10 = 0;
    uVar11 = 0;
    iVar6 = FUN_80114e4c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                         param_11,pfVar9,0,0,param_14,param_15,param_16);
    if (iVar6 == 0) {
      *(code **)(param_11 + 0xe8) = FUN_801e7bdc;
      *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffdf;
      dVar15 = (double)FLOAT_803e6674;
      *(float *)(iVar1 + 0x280) = FLOAT_803e6674;
      *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) | 4;
      if (param_12 != '\0') {
        param_2 = (double)FLOAT_803dc074;
        dVar15 = (double)FUN_8002fb40(dVar15,param_2);
      }
      if (*(short *)(iVar4 + 0xb4) == -1) {
        if (*(char *)(param_11 + 0x56) != '\0') {
          iVar6 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x44))();
          if (iVar6 != -1) {
            uVar8 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x38))
                              (*(int *)(iVar1 + 0x9b4),iVar6);
            *(undefined2 *)(iVar1 + 0x9cc) = uVar8;
            uVar8 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x30))
                              (*(int *)(iVar1 + 0x9b4),iVar6);
            *(undefined2 *)(iVar1 + 0x9ce) = uVar8;
            *(undefined2 *)(iVar1 + 0x9d0) = *(undefined2 *)(iVar1 + 0x9cc);
            *(undefined *)(iVar1 + 0x9d2) = 0;
            iVar12 = (int)*(short *)(iVar1 + 0x9cc);
            piVar7 = (int *)FUN_800395a4(iVar4,8);
            iVar6 = iVar12 >> 0x1f;
            iVar10 = iVar12 / 10 + iVar6;
            *piVar7 = (iVar12 + (iVar10 - (iVar10 >> 0x1f)) * -10) * 0x100;
            piVar7 = (int *)FUN_800395a4(iVar4,7);
            iVar10 = 0x66666667;
            iVar2 = iVar12 / 10 + iVar6;
            iVar2 = iVar2 - (iVar2 >> 0x1f);
            iVar3 = iVar2 / 10 + (iVar2 >> 0x1f);
            *piVar7 = (iVar2 + (iVar3 - (iVar3 >> 0x1f)) * -10) * 0x100;
            iVar6 = iVar12 / 100 + iVar6;
            iVar6 = iVar6 - (iVar6 >> 0x1f);
            if (9 < iVar6) {
              iVar6 = 9;
            }
            pfVar9 = (float *)0x0;
            piVar7 = (int *)FUN_800395a4(iVar4,6);
            *piVar7 = iVar6 << 8;
          }
          *(undefined *)(param_11 + 0x56) = 0;
          *(code **)(param_11 + 0xec) = FUN_801e7794;
        }
        iVar6 = (**(code **)(**(int **)(*(int *)(iVar1 + 0x9b4) + 0x68) + 0x44))();
        dVar15 = extraout_f1_00;
        if (iVar6 != -1) {
          FUN_8011f6d0(0x12);
          dVar15 = (double)FUN_8011f6ac(10);
        }
      }
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
        switch(*(undefined *)(param_11 + iVar6 + 0x81)) {
        case 1:
          pfVar9 = (float *)(uint)*(byte *)(iVar1 + 0x9d5);
          dVar15 = (double)FUN_801e83b8(iVar4,iVar1,(int)pfVar9,iVar10,uVar11,param_14,param_15,
                                        param_16);
          *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) | 2;
          break;
        case 2:
          (**(code **)(*DAT_803dd70c + 0x14))(iVar4,iVar1,3);
          pfVar9 = local_28;
          iVar10 = 0x50;
          uVar11 = 0;
          param_14 = *DAT_803dd734;
          dVar15 = (double)(**(code **)(param_14 + 0xc))(iVar4,0x7ef);
          *(undefined *)(iVar1 + 0x9d6) = 0;
          break;
        case 3:
          pfVar9 = (float *)0x2;
          iVar10 = *DAT_803dd70c;
          dVar15 = (double)(**(code **)(iVar10 + 0x14))(iVar4,iVar1);
          *(byte *)(iVar1 + 0x9d4) = *(byte *)(iVar1 + 0x9d4) | 0x20;
          *(undefined *)(iVar1 + 0x9d6) = 0xff;
          break;
        case 4:
          if (*(short *)(iVar5 + 0x46) == 0) {
            dVar15 = (double)FUN_80055464(dVar15,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8,0xf,'\0',pfVar9,iVar10,uVar11,param_14,param_15,
                                          param_16);
          }
          else {
            dVar15 = (double)FUN_80055464(dVar15,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8,0xe,'\0',pfVar9,iVar10,uVar11,param_14,param_15,
                                          param_16);
          }
          break;
        case 5:
          iVar2 = FUN_8001496c();
          if (iVar2 == 0x10) {
            piVar7 = (int *)FUN_80014964();
            dVar15 = (double)(**(code **)(*piVar7 + 0x10))(0);
          }
          break;
        case 6:
          iVar2 = FUN_8001496c();
          if (iVar2 == 0x10) {
            piVar7 = (int *)FUN_80014964();
            dVar15 = (double)(**(code **)(*piVar7 + 0x10))(2);
          }
          break;
        case 7:
          iVar2 = FUN_8001496c();
          if (iVar2 == 0x10) {
            piVar7 = (int *)FUN_80014964();
            dVar15 = (double)(**(code **)(*piVar7 + 0x10))(4);
          }
          break;
        case 9:
          dVar15 = (double)FUN_8029700c(iVar5,(uint)*(byte *)(iVar1 + 0x9d5));
          break;
        case 10:
          dVar15 = (double)FUN_8029700c(iVar5,-(uint)*(byte *)(iVar1 + 0x9d5));
          break;
        case 0xb:
          pfVar9 = local_28;
          iVar10 = 0x50;
          uVar11 = 0;
          param_14 = *DAT_803dd734;
          dVar15 = (double)(**(code **)(param_14 + 0xc))(iVar4,0x7ef);
          break;
        case 0xc:
          *(undefined *)(iVar1 + 0x9d5) = 1;
          uVar13 = (uint)*(byte *)(iVar1 + 0x9d5);
          piVar7 = (int *)FUN_800395a4(iVar4,8);
          *piVar7 = (uVar13 % 10) * 0x100;
          piVar7 = (int *)FUN_800395a4(iVar4,7);
          iVar10 = 0x66666667;
          *piVar7 = ((uVar13 / 10) % 10) * 0x100;
          uVar13 = uVar13 / 100;
          if (9 < uVar13) {
            uVar13 = 9;
          }
          pfVar9 = (float *)0x0;
          piVar7 = (int *)FUN_800395a4(iVar4,6);
          *piVar7 = uVar13 << 8;
        }
      }
      *(undefined *)(iVar4 + 0x36) = *(undefined *)(iVar1 + 0x9d6);
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
      (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
    }
  }
  FUN_80286884();
  return;
}

