// Function: FUN_8014bcf0
// Entry: 8014bcf0
// Size: 1056 bytes

void FUN_8014bcf0(double param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  byte bVar6;
  double extraout_f1;
  double extraout_f1_00;
  double dVar7;
  
  iVar1 = FUN_8002bac4();
  iVar2 = FUN_8002ba84();
  if (((*(int *)(param_10 + 0x29c) == 0) || ((*(uint *)(param_10 + 0x2e4) & 0x10000) != 0)) ||
     ((*(int *)(param_10 + 0x29c) == iVar1 && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xff7ff9ff;
    if (((*(uint *)(param_10 + 0x2e4) & 0x10000) != 0) ||
       ((*(int *)(param_10 + 0x29c) == iVar1 && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xdfffffff;
    }
  }
  else {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xff7fffff;
    iVar3 = (**(code **)(*DAT_803dd6d0 + 0x3c))();
    if (iVar3 == param_9) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x800200;
    }
    uVar4 = (uint)*(ushort *)(param_10 + 0x2a4);
    if (uVar4 < ((int)*(float *)(param_10 + 0x2ac) & 0xffffU)) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x400;
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xfffffdff;
      param_1 = extraout_f1;
    }
    else {
      param_1 = (double)*(float *)(param_10 + 0x2a8);
      if (uVar4 < ((int)*(float *)(param_10 + 0x2a8) & 0xffffU)) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x200;
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xfffffbff;
      }
      else if (((int)((double)FLOAT_803e326c * param_1) & 0xffffU) < uVar4) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xdffff9ff;
      }
    }
  }
  *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xf890fff7;
  if ((iVar2 != 0) &&
     (cVar5 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x40))(iVar2), param_1 = extraout_f1_00,
     cVar5 != '\0')) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x200000;
  }
  if (((*(int *)(param_10 + 0x29c) == iVar1) && (bVar6 = FUN_80296434(iVar1), bVar6 != 0)) &&
     (*(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 8,
     (*(uint *)(param_10 + 0x2e4) & 0x2000) != 0)) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xff7ff9ff;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x20000600) != 0) {
    if ((*(uint *)(param_10 + 0x2e4) & 0x1000) == 0) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x1000000;
    }
    else {
      cVar5 = FUN_8014a5b0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10,(float *)(param_9 + 0x18),
                           (float *)(*(int *)(param_10 + 0x29c) + 0x18));
      if (cVar5 != '\0') {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x1000000;
      }
      if ((*(uint *)(param_10 + 0x2dc) & 0x1000000) == 0) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xdfffffff;
      }
    }
    if ((*(ushort *)(param_10 + 0x2a0) < 2) || (5 < *(ushort *)(param_10 + 0x2a0))) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x400000;
    }
    else if ((*(uint *)(param_10 + 0x2dc) & 0x1000000) != 0) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x2000000;
    }
    if ((*(uint *)(param_10 + 0x2e4) & 0x4000) == 0) {
      iVar1 = *(int *)(param_10 + 0x29c);
      param_2 = (double)(*(float *)(iVar1 + 0x2c) * *(float *)(iVar1 + 0x2c));
      dVar7 = FUN_80293900((double)(float)(param_2 +
                                          (double)(*(float *)(iVar1 + 0x24) *
                                                   *(float *)(iVar1 + 0x24) +
                                                  *(float *)(iVar1 + 0x28) *
                                                  *(float *)(iVar1 + 0x28))));
      if ((double)FLOAT_803e3268 < dVar7) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x4000000;
      }
    }
    uVar4 = *(uint *)(param_10 + 0x2dc);
    if ((((uVar4 & 0x600) != 0) && ((uVar4 & 0x6800000) != 0)) && ((uVar4 & 0x1000000) != 0)) {
      *(uint *)(param_10 + 0x2dc) = uVar4 | 0x20000000;
    }
    if ((*(uint *)(param_10 + 0x2dc) & 0x20000000) != 0) {
      if ((*(uint *)(param_10 + 0x2e4) & 0x40) == 0) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0xf0000;
      }
      else {
        FUN_8014a764((double)*(float *)(param_10 + 0x2ac),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8);
      }
    }
  }
  if (*(short *)(param_10 + 0x2b0) == 0) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x800;
  }
  return;
}

