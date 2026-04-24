// Function: FUN_8020fdb0
// Entry: 8020fdb0
// Size: 900 bytes

void FUN_8020fdb0(short *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  local_2c = FLOAT_803e6720;
  iVar2 = *piVar3;
  if (iVar2 != 0) {
    iVar1 = FUN_8003687c(iVar2,&local_30,0,0);
    if (((iVar1 == 0x15) && (-1 < *(char *)(piVar3 + 0x29))) &&
       (FUN_80036450(iVar2,local_30,0x15,1,0), *(char *)((int)piVar3 + 0xa5) < '\0')) {
      *(char *)(piVar3 + 0x29) = *(char *)(piVar3 + 0x29) + -1;
      FUN_8000bb18(param_1,0xf2);
      FUN_8000bb18(param_1,0x14);
      FUN_8000bb18(param_1,*(uint *)(&DAT_8032a350 + *(char *)(piVar3 + 0x29) * 4) & 0xffff);
      *(undefined *)((int)piVar3 + 0xa5) = 0x14;
      piVar3[0x27] = piVar3[0x27] + -0x28;
      if (*(char *)(piVar3 + 0x29) < '\0') {
        FUN_8009ab70((double)FLOAT_803e6724,param_1,1,1,1,1,0,1,0);
        iVar2 = *piVar3;
        if (iVar2 != 0) {
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x3c))(iVar2,0);
        }
        if ((param_1[0x23] == 0x389) && (iVar2 = FUN_80036e58(0x1e,param_1,&local_2c), iVar2 != 0))
        {
          FUN_80037cb0(param_1,iVar2);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,2);
        }
        if ((param_1[0x23] == 0x16d) || (param_1[0x23] == 0x170)) {
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,1);
        }
        else {
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,3);
        }
        *(byte *)((int)piVar3 + 0xaa) = *(byte *)((int)piVar3 + 0xaa) & 0xbf | 0x40;
        piVar3[0x2b] = (int)FLOAT_803e670c;
        uStack36 = (int)*param_1 ^ 0x80000000;
        local_28 = 0x43300000;
        dVar4 = (double)FUN_80293e80((double)((FLOAT_803e672c *
                                              (float)((double)CONCAT44(0x43300000,uStack36) -
                                                     DOUBLE_803e6718)) / FLOAT_803e6730));
        piVar3[9] = (int)(float)((double)FLOAT_803e6728 * dVar4);
        uStack28 = FUN_800221a0(0x28,100);
        dVar4 = DOUBLE_803e6718;
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        piVar3[10] = (int)(FLOAT_803e6734 *
                          (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6718));
        uStack20 = (int)*param_1 ^ 0x80000000;
        local_18 = 0x43300000;
        dVar4 = (double)FUN_80294204((double)((FLOAT_803e672c *
                                              (float)((double)CONCAT44(0x43300000,uStack20) - dVar4)
                                              ) / FLOAT_803e6730));
        piVar3[0xb] = (int)(float)((double)FLOAT_803e6728 * dVar4);
        FUN_8002b9ec();
        iVar2 = FUN_802972a8();
        if ((iVar2 != 0) && (*(int *)(iVar2 + 0xb8) != 0)) {
          *(float *)(*(int *)(iVar2 + 0xb8) + 0x4c4) = FLOAT_803e6738;
        }
      }
      else {
        FUN_80030334((double)FLOAT_803e66f0,param_1,*(ushort *)(piVar3 + 0x2a) + 9,0);
        piVar3[0xc] = (int)FLOAT_803e66f4;
      }
    }
    if ((*piVar3 != 0) && (iVar2 = (**(code **)(**(int **)(*piVar3 + 0x68) + 0x38))(), iVar2 == 2))
    {
      FUN_8020f594(param_1,*piVar3,0,0,0,0,0,0,0);
    }
    if (-1 < *(char *)((int)piVar3 + 0xa5)) {
      *(char *)((int)piVar3 + 0xa5) = *(char *)((int)piVar3 + 0xa5) - DAT_803db410;
    }
  }
  return;
}

