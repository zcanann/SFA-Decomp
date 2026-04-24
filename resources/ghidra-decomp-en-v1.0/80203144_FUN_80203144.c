// Function: FUN_80203144
// Entry: 80203144
// Size: 584 bytes

void FUN_80203144(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  
  uVar7 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  iVar5 = *(int *)(iVar3 + 0x40c);
  local_30 = FLOAT_803e62b0;
  iVar4 = *(int *)(iVar1 + 0x4c);
  uStack28 = (uint)*(ushort *)(iVar3 + 0x3fe);
  local_20 = 0x43300000;
  iVar2 = (**(code **)(*DAT_803dcab8 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e62e0),iVar1,
                     param_3,0x8000);
  if ((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) {
    iVar2 = FUN_80036e58(0x24,iVar1,&local_30);
  }
  if (iVar2 == 0) {
    if ((((*(byte *)(iVar3 + 0x404) & 0x10) != 0) && ((*(byte *)(iVar3 + 0x404) & 2) == 0)) &&
       ((*(byte *)(iVar4 + 0x2b) & 2) != 0)) {
      iVar2 = FUN_80036e58(0x24,iVar1,0);
    }
  }
  if ((iVar2 == 0) || ((*(byte *)(iVar3 + 0x404) & 2) != 0)) {
    iVar2 = FUN_8002b9ec();
    if (iVar2 == 0) {
      dVar6 = (double)FLOAT_803e6354;
    }
    else {
      local_2c = *(float *)(iVar2 + 0x18) - *(float *)(iVar1 + 0x18);
      local_28 = *(float *)(iVar2 + 0x1c) - *(float *)(iVar1 + 0x1c);
      local_24 = *(float *)(iVar2 + 0x20) - *(float *)(iVar1 + 0x20);
      dVar6 = (double)FUN_802931a0((double)(local_24 * local_24 +
                                           local_2c * local_2c + local_28 * local_28));
    }
    if ((*(float *)(iVar5 + 0x10) < *(float *)(iVar5 + 0xc)) && (dVar6 < (double)FLOAT_803e6384)) {
      FUN_8000bb18(iVar1,DAT_80329644 & 0xffff);
      uStack28 = FUN_800221a0(0x32,0xfa);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar5 + 0x10) =
           *(float *)(iVar5 + 0x10) +
           (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6368);
    }
    *(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + FLOAT_803db414;
  }
  else {
    (**(code **)(*DAT_803dcab8 + 0x28))
              (iVar1,param_3,iVar3 + 0x35c,(int)*(short *)(iVar3 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar2;
    *(undefined *)(param_3 + 0x349) = 0;
    FUN_80037200(iVar1,3);
    *(undefined2 *)(iVar3 + 0x402) = 1;
  }
  FUN_80286124();
  return;
}

