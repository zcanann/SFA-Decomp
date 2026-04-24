// Function: FUN_8003bce8
// Entry: 8003bce8
// Size: 336 bytes

/* WARNING: Removing unreachable block (ram,0x8003be0c) */
/* WARNING: Removing unreachable block (ram,0x8003be14) */

undefined4
FUN_8003bce8(undefined4 param_1,undefined2 *param_2,undefined2 *param_3,undefined2 *param_4)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_78;
  float local_74;
  float local_70;
  float local_68;
  float local_64;
  float local_60;
  float local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar2 = FUN_8003bb84(param_1,&local_78);
  if (iVar2 == 0) {
    uVar3 = 0;
  }
  else {
    dVar5 = (double)FUN_80291f44(-(double)local_60);
    if ((double)FLOAT_803dea08 <= dVar5) {
      dVar6 = (double)FUN_802923c4((double)local_74,(double)local_78);
      dVar7 = (double)FLOAT_803dea04;
      dVar6 = (double)(float)(dVar6 - dVar7);
    }
    else if (dVar5 <= (double)FLOAT_803dea0c) {
      dVar6 = (double)FUN_802923c4((double)local_74,(double)local_78);
      dVar7 = (double)FLOAT_803dea04;
      dVar6 = (double)(float)(dVar7 - dVar6);
    }
    else {
      dVar6 = (double)FUN_802923c4((double)local_70,(double)local_50);
      dVar7 = (double)FUN_802923c4((double)local_68,(double)local_64);
    }
    fVar1 = FLOAT_803dea14;
    dVar8 = (double)FLOAT_803dea10;
    *param_4 = (short)(int)((float)(dVar8 * dVar7) / FLOAT_803dea14);
    *param_3 = (short)(int)((float)(dVar8 * dVar5) / fVar1);
    *param_2 = (short)(int)((float)(dVar8 * dVar6) / fVar1);
    uVar3 = 1;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return uVar3;
}

