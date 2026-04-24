// Function: FUN_8014b878
// Entry: 8014b878
// Size: 1056 bytes

void FUN_8014b878(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  double dVar6;
  
  iVar1 = FUN_8002b9ec();
  iVar2 = FUN_8002b9ac();
  if (((*(int *)(param_2 + 0x29c) == 0) || ((*(uint *)(param_2 + 0x2e4) & 0x10000) != 0)) ||
     ((*(int *)(param_2 + 0x29c) == iVar1 && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xff7ff9ff;
    if (((*(uint *)(param_2 + 0x2e4) & 0x10000) != 0) ||
       ((*(int *)(param_2 + 0x29c) == iVar1 && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xdfffffff;
    }
  }
  else {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xff7fffff;
    iVar3 = (**(code **)(*DAT_803dca50 + 0x3c))();
    if (iVar3 == param_1) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x800200;
    }
    uVar4 = (uint)*(ushort *)(param_2 + 0x2a4);
    if (uVar4 < ((int)*(float *)(param_2 + 0x2ac) & 0xffffU)) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x400;
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xfffffdff;
    }
    else if (uVar4 < ((int)*(float *)(param_2 + 0x2a8) & 0xffffU)) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x200;
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xfffffbff;
    }
    else if (((int)(FLOAT_803e25d8 * *(float *)(param_2 + 0x2a8)) & 0xffffU) < uVar4) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xdffff9ff;
    }
  }
  *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xf890fff7;
  if ((iVar2 != 0) && (cVar5 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x40))(iVar2), cVar5 != '\0')
     ) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x200000;
  }
  if (((*(int *)(param_2 + 0x29c) == iVar1) && (iVar1 = FUN_80295cd4(iVar1), iVar1 != 0)) &&
     (*(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 8,
     (*(uint *)(param_2 + 0x2e4) & 0x2000) != 0)) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xff7ff9ff;
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x20000600) != 0) {
    if ((*(uint *)(param_2 + 0x2e4) & 0x1000) == 0) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x1000000;
    }
    else {
      cVar5 = FUN_8014a150(param_1,param_2,param_1 + 0x18,*(int *)(param_2 + 0x29c) + 0x18);
      if (cVar5 != '\0') {
        *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x1000000;
      }
      if ((*(uint *)(param_2 + 0x2dc) & 0x1000000) == 0) {
        *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xdfffffff;
      }
    }
    if ((*(ushort *)(param_2 + 0x2a0) < 2) || (5 < *(ushort *)(param_2 + 0x2a0))) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x400000;
    }
    else if ((*(uint *)(param_2 + 0x2dc) & 0x1000000) != 0) {
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x2000000;
    }
    if ((*(uint *)(param_2 + 0x2e4) & 0x4000) == 0) {
      iVar1 = *(int *)(param_2 + 0x29c);
      dVar6 = (double)FUN_802931a0((double)(*(float *)(iVar1 + 0x2c) * *(float *)(iVar1 + 0x2c) +
                                           *(float *)(iVar1 + 0x24) * *(float *)(iVar1 + 0x24) +
                                           *(float *)(iVar1 + 0x28) * *(float *)(iVar1 + 0x28)));
      if ((double)FLOAT_803e25d4 < dVar6) {
        *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x4000000;
      }
    }
    uVar4 = *(uint *)(param_2 + 0x2dc);
    if ((((uVar4 & 0x600) != 0) && ((uVar4 & 0x6800000) != 0)) && ((uVar4 & 0x1000000) != 0)) {
      *(uint *)(param_2 + 0x2dc) = uVar4 | 0x20000000;
    }
    if ((*(uint *)(param_2 + 0x2dc) & 0x20000000) != 0) {
      if ((*(uint *)(param_2 + 0x2e4) & 0x40) == 0) {
        *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0xf0000;
      }
      else {
        FUN_8014a304((double)*(float *)(param_2 + 0x2ac),param_1,param_2);
      }
    }
  }
  if (*(short *)(param_2 + 0x2b0) == 0) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x800;
  }
  return;
}

