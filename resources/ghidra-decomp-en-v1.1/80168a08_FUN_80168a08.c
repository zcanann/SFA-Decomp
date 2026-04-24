// Function: FUN_80168a08
// Entry: 80168a08
// Size: 496 bytes

void FUN_80168a08(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,int param_15,undefined4 param_16)

{
  uint uVar1;
  uint uVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar6 = *(int *)(iVar5 + 0x40c);
  dVar8 = (double)FLOAT_803e3d38;
  dVar7 = (double)(float)((double)CONCAT44(0x43300000,
                                           (int)*(char *)(*(int *)(uVar1 + 0x4c) + 0x28) ^
                                           0x80000000) - DOUBLE_803e3d08);
  FLOAT_803de718 = (float)(dVar8 + (double)(float)(dVar7 / (double)FLOAT_803e3d3c));
  pfVar3 = (float *)param_14;
  if ((*(uint *)(param_11 + 0x314) & 1) != 0) {
    *(uint *)(param_11 + 0x314) = *(uint *)(param_11 + 0x314) & 0xfffffffe;
    dVar7 = (double)FUN_8000bb38(uVar1,0x273);
    pfVar3 = (float *)param_14;
  }
  if ((*(uint *)(param_11 + 0x314) & 0x80) != 0) {
    uVar2 = FUN_80022264(0,2);
    *(char *)(iVar6 + 0x4a) = (char)uVar2;
    *(uint *)(param_11 + 0x314) = *(uint *)(param_11 + 0x314) & 0xffffff7f;
    dVar7 = (double)FUN_8000bb38(uVar1,0x274);
    for (iVar4 = (2 - (uint)*(byte *)(iVar6 + 0x4a)) * 10; iVar4 != 0; iVar4 = iVar4 + -1) {
      param_12 = 4;
      param_13 = 0xffffffff;
      pfVar3 = &FLOAT_803de718;
      param_15 = *DAT_803dd708;
      dVar7 = (double)(**(code **)(param_15 + 8))(uVar1,0x711,0);
    }
  }
  if ((*(uint *)(param_11 + 0x314) & 0x40) != 0) {
    *(uint *)(param_11 + 0x314) = *(uint *)(param_11 + 0x314) & 0xffffffbf;
    dVar7 = (double)FUN_80168820(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                                 iVar5,'\0',param_12,param_13,pfVar3,param_15,param_16);
  }
  if ((*(uint *)(param_11 + 0x314) & 0x800) != 0) {
    *(uint *)(param_11 + 0x314) = *(uint *)(param_11 + 0x314) & 0xfffff7ff;
    FUN_80168820(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,iVar5,'\x01',
                 param_12,param_13,pfVar3,param_15,param_16);
  }
  if ((*(uint *)(param_11 + 0x314) & 0x200) != 0) {
    *(uint *)(param_11 + 0x314) = *(uint *)(param_11 + 0x314) & 0xfffffdff;
    FUN_8000bb38(uVar1,0x275);
  }
  if ((*(uint *)(param_11 + 0x314) & 0x400) != 0) {
    *(undefined *)(iVar6 + 0x4a) = 3;
    iVar5 = 10;
    do {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x710,0,4,0xffffffff,&FLOAT_803de718);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    *(uint *)(param_11 + 0x314) = *(uint *)(param_11 + 0x314) & 0xfffffbff;
  }
  FUN_8028688c();
  return;
}

