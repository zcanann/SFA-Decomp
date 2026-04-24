// Function: FUN_80210428
// Entry: 80210428
// Size: 900 bytes

void FUN_80210428(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int *piVar5;
  double dVar6;
  int local_30;
  float local_2c [2];
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  piVar5 = *(int **)(param_9 + 0x5c);
  local_2c[0] = FLOAT_803e73b8;
  iVar4 = *piVar5;
  if (iVar4 != 0) {
    iVar1 = FUN_80036974(iVar4,&local_30,(int *)0x0,(uint *)0x0);
    if ((iVar1 == 0x15) && (-1 < *(char *)(piVar5 + 0x29))) {
      uVar2 = 1;
      uVar3 = 0;
      FUN_80036548(iVar4,local_30,'\x15',1,0);
      if (*(char *)((int)piVar5 + 0xa5) < '\0') {
        *(char *)(piVar5 + 0x29) = *(char *)(piVar5 + 0x29) + -1;
        FUN_8000bb38((uint)param_9,0xf2);
        FUN_8000bb38((uint)param_9,0x14);
        FUN_8000bb38((uint)param_9,
                     (ushort)*(undefined4 *)(&DAT_8032afa8 + *(char *)(piVar5 + 0x29) * 4));
        *(undefined *)((int)piVar5 + 0xa5) = 0x14;
        piVar5[0x27] = piVar5[0x27] + -0x28;
        if (*(char *)(piVar5 + 0x29) < '\0') {
          FUN_8009adfc((double)FLOAT_803e73bc,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,1,1,1,1,0,1,0);
          iVar4 = *piVar5;
          if (iVar4 != 0) {
            (**(code **)(**(int **)(iVar4 + 0x68) + 0x3c))(iVar4,0);
          }
          if ((param_9[0x23] == 0x389) && (iVar4 = FUN_80036f50(0x1e,param_9,local_2c), iVar4 != 0))
          {
            FUN_80037da8((int)param_9,iVar4);
            (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,2);
          }
          if ((param_9[0x23] == 0x16d) || (param_9[0x23] == 0x170)) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,1);
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,3);
          }
          *(byte *)((int)piVar5 + 0xaa) = *(byte *)((int)piVar5 + 0xaa) & 0xbf | 0x40;
          piVar5[0x2b] = (int)FLOAT_803e73a4;
          uStack_24 = (int)*param_9 ^ 0x80000000;
          local_2c[1] = 176.0;
          dVar6 = (double)FUN_802945e0();
          piVar5[9] = (int)(float)((double)FLOAT_803e73c0 * dVar6);
          uStack_1c = FUN_80022264(0x28,100);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          piVar5[10] = (int)(FLOAT_803e73cc *
                            (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e73b0));
          uStack_14 = (int)*param_9 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar6 = (double)FUN_80294964();
          piVar5[0xb] = (int)(float)((double)FLOAT_803e73c0 * dVar6);
          iVar4 = FUN_8002bac4();
          iVar4 = FUN_80297a08(iVar4);
          if ((iVar4 != 0) && (*(int *)(iVar4 + 0xb8) != 0)) {
            *(float *)(*(int *)(iVar4 + 0xb8) + 0x4c4) = FLOAT_803e73d0;
          }
        }
        else {
          FUN_8003042c((double)FLOAT_803e7388,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,*(ushort *)(piVar5 + 0x2a) + 9,0,uVar2,uVar3,in_r8,in_r9,
                       in_r10);
          piVar5[0xc] = (int)FLOAT_803e738c;
        }
      }
    }
    if ((*piVar5 != 0) && (iVar4 = (**(code **)(**(int **)(*piVar5 + 0x68) + 0x38))(), iVar4 == 2))
    {
      FUN_8020fc0c(param_9,(undefined2 *)*piVar5,0,0,0,0,'\0',0,0);
    }
    if (-1 < *(char *)((int)piVar5 + 0xa5)) {
      *(char *)((int)piVar5 + 0xa5) = *(char *)((int)piVar5 + 0xa5) - DAT_803dc070;
    }
  }
  return;
}

