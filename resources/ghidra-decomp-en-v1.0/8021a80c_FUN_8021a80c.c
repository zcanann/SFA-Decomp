// Function: FUN_8021a80c
// Entry: 8021a80c
// Size: 892 bytes

/* WARNING: Removing unreachable block (ram,0x8021ab60) */

void FUN_8021a80c(int param_1)

{
  char cVar3;
  int iVar1;
  int iVar2;
  int *piVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f31;
  float local_38 [2];
  longlong local_30;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_1 + 0x4c);
  local_38[0] = FLOAT_803e69f4;
  piVar4 = *(int **)(param_1 + 0xb8);
  if ((*(byte *)((int)piVar4 + 0x31) >> 6 & 1) != 0) {
    FUN_80099d84((double)FLOAT_803e69f8,(double)FLOAT_803e69f0,param_1,6,0);
  }
  if ((*(short *)(param_1 + 0x46) == 0x86a) || (*(short *)(param_1 + 0x46) == 0x86b)) {
    iVar5 = FUN_8001ffb4(0x609);
    if (iVar5 != 0) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    }
  }
  else if ((*piVar4 == 0) && (cVar3 = FUN_8002e04c(), cVar3 != '\0')) {
    iVar1 = FUN_8002bdf4(0x20,0x477);
    *(undefined *)(iVar1 + 4) = 2;
    *(undefined *)(iVar1 + 5) = 1;
    *(byte *)(iVar1 + 5) = *(byte *)(iVar1 + 5) | *(byte *)(iVar5 + 5) & 0x18;
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    iVar5 = FUN_8002df90(iVar1,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                         *(undefined4 *)(param_1 + 0x30));
    *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) | 0x4000;
    *(undefined4 *)(iVar5 + 0xf4) = 1;
    *piVar4 = iVar5;
  }
  else {
    if (-1 < *(char *)((int)piVar4 + 0x31)) {
      iVar1 = FUN_8001ffb4(0x609);
      if (iVar1 != 0) {
        FUN_80035f00(param_1);
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
        *(byte *)((int)piVar4 + 0x31) = *(byte *)((int)piVar4 + 0x31) & 0x7f | 0x80;
        iVar5 = FUN_80036e58(10,param_1,local_38);
        if ((iVar5 != 0) && (*(short *)(iVar5 + 0x46) == 0x419)) {
          *(undefined4 *)(iVar5 + 0xf4) = 0;
          piVar4[1] = 0;
        }
        goto LAB_8021ab60;
      }
      dVar7 = (double)FUN_80021370((double)(FLOAT_803db418 *
                                            (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80))
                                            * FLOAT_803e69fc - (float)piVar4[9]),
                                   (double)FLOAT_803e6a00,(double)FLOAT_803db414);
      dVar8 = (double)(FLOAT_803e6a04 * FLOAT_803db414);
      if ((dVar8 <= dVar7) && (dVar8 = dVar7, (double)(FLOAT_803e6a08 * FLOAT_803db414) < dVar7)) {
        dVar8 = (double)(FLOAT_803e6a08 * FLOAT_803db414);
      }
      piVar4[9] = (int)(float)((double)(float)piVar4[9] + dVar8);
      iVar1 = 0;
      dVar8 = (double)FLOAT_803e6a0c;
      do {
        iVar2 = FUN_800395d8(param_1,iVar1);
        if (iVar2 != 0) {
          local_30 = (longlong)(int)((double)(float)piVar4[9] / dVar8);
          *(short *)(iVar2 + 4) = (short)(int)((double)(float)piVar4[9] / dVar8);
        }
        iVar1 = iVar1 + 1;
      } while (iVar1 < 9);
      if (*piVar4 != 0) {
        local_30 = (longlong)(int)(float)piVar4[9];
        *(short *)(*piVar4 + 4) = (short)(int)(float)piVar4[9];
        iVar1 = FUN_80036e58(10,param_1,local_38);
        if ((iVar1 != 0) && (*(short *)(iVar1 + 0x46) == 0x419)) {
          *(undefined4 *)(iVar1 + 0xf4) = 1;
          piVar4[1] = iVar1;
          *(undefined2 *)(iVar1 + 4) = *(undefined2 *)(*piVar4 + 4);
          *(undefined4 *)(*piVar4 + 0xf4) = 1;
        }
        if ((piVar4[1] != 0) && ((*(ushort *)(piVar4[1] + 0xb0) & 0x40) != 0)) {
          piVar4[1] = 0;
        }
      }
    }
    if (-1 < *(char *)((int)piVar4 + 0x31)) {
      iVar1 = FUN_8001ffb4(0xc67);
      if (iVar1 == 0) {
        FUN_800200e8(0xea4,0);
      }
      else if ((*(float *)(param_1 + 0xc) < FLOAT_803e6a10) ||
              (FLOAT_803e6a14 < *(float *)(param_1 + 0xc))) {
        FUN_800200e8(0xea4,1);
      }
      else {
        FUN_800200e8((int)*(short *)(iVar5 + 0x1e),1);
      }
    }
  }
LAB_8021ab60:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

