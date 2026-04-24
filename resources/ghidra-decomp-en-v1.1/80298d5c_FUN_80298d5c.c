// Function: FUN_80298d5c
// Entry: 80298d5c
// Size: 808 bytes

/* WARNING: Removing unreachable block (ram,0x80299060) */
/* WARNING: Removing unreachable block (ram,0x80298f14) */
/* WARNING: Removing unreachable block (ram,0x80298d6c) */

undefined4
FUN_80298d5c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  double dVar6;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(byte *)(iVar4 + 0x3f3) = *(byte *)(iVar4 + 0x3f3) & 0xef;
    if (*(short *)(iVar4 + 0x80a) == 0xc55) {
      *(undefined *)(iVar4 + 0x41c) = 0x14;
    }
    else {
      *(undefined *)(iVar4 + 0x41c) = 10;
    }
    FUN_80035f84(param_9);
  }
  if (((*(byte *)(iVar4 + 0x3f0) >> 5 & 1) == 0) && (FLOAT_803e8b3c != *(float *)(iVar4 + 0x784))) {
    param_10[0xc2] = 0;
    return 0x42;
  }
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0x85) {
    *(float *)(iVar4 + 0x7d4) =
         *(float *)(iVar4 + 0x7d4) + (float)((double)FLOAT_803e8b6c * param_1) / FLOAT_803e8b88;
    *(float *)(iVar4 + 0x7d4) =
         (float)((double)FLOAT_803e8b30 * param_1 + (double)*(float *)(iVar4 + 0x7d4));
    dVar6 = (double)*(float *)(iVar4 + 0x7d4);
    if ((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x41c)) -
                       DOUBLE_803e8bd0) <= dVar6) {
      FUN_8000bb38(param_9,0x219);
      iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x35c);
      iVar4 = (int)*(short *)(iVar3 + 4) - (uint)*(byte *)(iVar4 + 0x41c);
      if (iVar4 < 0) {
        iVar4 = 0;
      }
      else if (*(short *)(iVar3 + 6) < iVar4) {
        iVar4 = (int)*(short *)(iVar3 + 6);
      }
      *(short *)(iVar3 + 4) = (short)iVar4;
      FUN_8003042c((double)FLOAT_803e8b3c,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x86,0,param_12,param_13,param_14,param_15,param_16);
      param_10[0xa8] = (uint)FLOAT_803e8b90;
    }
  }
  else {
    if (sVar1 < 0x85) {
      if (0x83 < sVar1) {
        if (*(char *)((int)param_10 + 0x346) == '\0') {
          return 0;
        }
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x85,0,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8b94;
        return 0;
      }
    }
    else if (sVar1 < 0x87) {
      if (((*(byte *)(iVar4 + 0x3f3) >> 4 & 1) == 0) &&
         (FLOAT_803e8b94 < *(float *)(param_9 + 0x98))) {
        iVar3 = FUN_8002ba84();
        if (iVar3 != 0) {
          FUN_80139280(iVar3);
        }
        uVar5 = FUN_8000bb38(param_9,0x21a);
        FUN_8016dea8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (undefined4 *)(param_9 + 0xc));
        *(byte *)(iVar4 + 0x3f3) = *(byte *)(iVar4 + 0x3f3) & 0xef | 0x10;
        FUN_80014acc((double)FLOAT_803e8bc8);
      }
      if (*(char *)((int)param_10 + 0x346) == '\0') {
        return 0;
      }
      *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
      param_10[0xc2] = (uint)FUN_802a58ac;
      return 2;
    }
    FUN_8000bb38(param_9,0x21b);
    fVar2 = FLOAT_803e8b3c;
    dVar6 = (double)FLOAT_803e8b3c;
    param_10[0xa5] = (uint)FLOAT_803e8b3c;
    param_10[0xa1] = (uint)fVar2;
    param_10[0xa0] = (uint)fVar2;
    *(float *)(param_9 + 0x24) = fVar2;
    *(float *)(param_9 + 0x28) = fVar2;
    *(float *)(param_9 + 0x2c) = fVar2;
    FUN_8003042c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0x84,0,
                 param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8bcc;
    *(float *)(iVar4 + 0x7d4) = FLOAT_803e8b3c;
    *(byte *)(iVar4 + 0x3f3) = *(byte *)(iVar4 + 0x3f3) & 0xef;
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar4 + 0x8b4) = 4;
      *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7 | 8;
    }
  }
  return 0;
}

