// Function: FUN_80221978
// Entry: 80221978
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x80221bf8) */

void FUN_80221978(undefined4 param_1,undefined4 param_2,int param_3,int *param_4)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  undefined4 uVar7;
  double extraout_f1;
  undefined8 in_f31;
  double dVar8;
  undefined8 uVar9;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar9 = FUN_802860d8();
  iVar4 = (int)((ulonglong)uVar9 >> 0x20);
  piVar5 = (int *)uVar9;
  bVar1 = false;
  if ((double)FLOAT_803e6c38 == extraout_f1) {
    for (iVar4 = 0; iVar4 < param_3; iVar4 = iVar4 + 1) {
      if (*piVar5 != 0) {
        FUN_8008fc7c();
        *piVar5 = 0;
      }
      piVar5 = piVar5 + 1;
    }
    if (*param_4 != 0) {
      FUN_8001cb3c(param_4);
    }
    uVar2 = 0;
  }
  else {
    dVar8 = extraout_f1;
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      if (*piVar5 == 0) {
        if (!bVar1) {
          local_58 = *(float *)(iVar4 + 0xc);
          local_54 = *(float *)(iVar4 + 0x10);
          local_50 = *(float *)(iVar4 + 0x14);
          iVar3 = FUN_800221a0(0,2000);
          uStack68 = iVar3 - 1000U ^ 0x80000000;
          local_48 = 0x43300000;
          local_58 = FLOAT_803e6c3c *
                     (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack68) -
                                                    DOUBLE_803e6c50)) + local_58;
          iVar3 = FUN_800221a0(0,2000);
          uStack60 = iVar3 - 1000U ^ 0x80000000;
          local_40 = 0x43300000;
          local_54 = FLOAT_803e6c3c *
                     (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                                    DOUBLE_803e6c50)) + local_54;
          iVar3 = FUN_800221a0(0,2000);
          uStack52 = iVar3 - 1000U ^ 0x80000000;
          local_38 = 0x43300000;
          local_50 = FLOAT_803e6c3c *
                     (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack52) -
                                                    DOUBLE_803e6c50)) + local_50;
          local_30 = (longlong)(int)FLOAT_803dc3a8;
          iVar3 = FUN_8008fb20((double)FLOAT_803dc3a0,(double)FLOAT_803dc3a4,iVar4 + 0xc,&local_58,
                               (int)FLOAT_803dc3a8,DAT_803dc3ac & 0xff,0);
          *piVar5 = iVar3;
          bVar1 = true;
        }
      }
      else {
        FUN_8008f904();
        *(ushort *)(*piVar5 + 0x20) = *(short *)(*piVar5 + 0x20) + (ushort)DAT_803db410;
        uStack68 = (uint)*(ushort *)(*piVar5 + 0x20);
        local_48 = 0x43300000;
        if (FLOAT_803dc3a8 < (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e6c48)) {
          FUN_8008fc7c();
          *piVar5 = 0;
        }
      }
      piVar5 = piVar5 + 1;
    }
    if (*param_4 == 0) {
      iVar4 = FUN_8001cc9c(iVar4,0x80,0x80,0xff,0);
      *param_4 = iVar4;
      if (*param_4 != 0) {
        FUN_8001dd88((double)FLOAT_803e6c38,(double)(float)(dVar8 * (double)FLOAT_803e6c40),
                     (double)FLOAT_803e6c38);
        FUN_8001dc38(dVar8,(double)(float)((double)FLOAT_803e6c44 + dVar8),*param_4);
      }
    }
    uVar2 = 1;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286124(uVar2);
  return;
}

