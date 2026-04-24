// Function: FUN_802985fc
// Entry: 802985fc
// Size: 808 bytes

/* WARNING: Removing unreachable block (ram,0x802987b4) */
/* WARNING: Removing unreachable block (ram,0x80298900) */

undefined4 FUN_802985fc(double param_1,int param_2,uint *param_3)

{
  short sVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_2 + 0xb8);
  *param_3 = *param_3 | 0x200000;
  if (*(char *)((int)param_3 + 0x27a) != '\0') {
    *(byte *)(iVar5 + 0x3f3) = *(byte *)(iVar5 + 0x3f3) & 0xef;
    if (*(short *)(iVar5 + 0x80a) == 0xc55) {
      *(undefined *)(iVar5 + 0x41c) = 0x14;
    }
    else {
      *(undefined *)(iVar5 + 0x41c) = 10;
    }
    FUN_80035e8c(param_2);
  }
  if (((*(byte *)(iVar5 + 0x3f0) >> 5 & 1) == 0) && (FLOAT_803e7ea4 != *(float *)(iVar5 + 0x784))) {
    param_3[0xc2] = 0;
    uVar3 = 0x42;
    goto LAB_80298900;
  }
  sVar1 = *(short *)(param_2 + 0xa0);
  if (sVar1 == 0x85) {
    *(float *)(iVar5 + 0x7d4) =
         *(float *)(iVar5 + 0x7d4) + (float)((double)FLOAT_803e7ed4 * param_1) / FLOAT_803e7ef0;
    *(float *)(iVar5 + 0x7d4) =
         (float)((double)FLOAT_803e7e98 * param_1 + (double)*(float *)(iVar5 + 0x7d4));
    if ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x41c)) - DOUBLE_803e7f38) <=
        *(float *)(iVar5 + 0x7d4)) {
      FUN_8000bb18(param_2,0x219);
      iVar4 = *(int *)(*(int *)(param_2 + 0xb8) + 0x35c);
      iVar5 = (int)*(short *)(iVar4 + 4) - (uint)*(byte *)(iVar5 + 0x41c);
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      else if (*(short *)(iVar4 + 6) < iVar5) {
        iVar5 = (int)*(short *)(iVar4 + 6);
      }
      *(short *)(iVar4 + 4) = (short)iVar5;
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0x86,0);
      param_3[0xa8] = (uint)FLOAT_803e7ef8;
    }
  }
  else if (sVar1 < 0x85) {
    if (sVar1 < 0x84) {
LAB_80298870:
      FUN_8000bb18(param_2,0x21b);
      fVar2 = FLOAT_803e7ea4;
      param_3[0xa5] = (uint)FLOAT_803e7ea4;
      param_3[0xa1] = (uint)fVar2;
      param_3[0xa0] = (uint)fVar2;
      *(float *)(param_2 + 0x24) = fVar2;
      *(float *)(param_2 + 0x28) = fVar2;
      *(float *)(param_2 + 0x2c) = fVar2;
      FUN_80030334(param_2,0x84,0);
      param_3[0xa8] = (uint)FLOAT_803e7f34;
      *(float *)(iVar5 + 0x7d4) = FLOAT_803e7ea4;
      *(byte *)(iVar5 + 0x3f3) = *(byte *)(iVar5 + 0x3f3) & 0xef;
      if ((DAT_803de44c != 0) && ((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar5 + 0x8b4) = 4;
        *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xf7 | 8;
      }
    }
    else if (*(char *)((int)param_3 + 0x346) != '\0') {
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0x85,0);
      param_3[0xa8] = (uint)FLOAT_803e7efc;
    }
  }
  else {
    if (0x86 < sVar1) goto LAB_80298870;
    if (((*(byte *)(iVar5 + 0x3f3) >> 4 & 1) == 0) && (FLOAT_803e7efc < *(float *)(param_2 + 0x98)))
    {
      iVar4 = FUN_8002b9ac();
      if (iVar4 != 0) {
        FUN_80138ef8();
      }
      FUN_8000bb18(param_2,0x21a);
      FUN_8016d9fc(param_2 + 0xc);
      *(byte *)(iVar5 + 0x3f3) = *(byte *)(iVar5 + 0x3f3) & 0xef | 0x10;
      FUN_80014aa0((double)FLOAT_803e7f30);
    }
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
      param_3[0xc2] = (uint)FUN_802a514c;
      uVar3 = 2;
      goto LAB_80298900;
    }
  }
  uVar3 = 0;
LAB_80298900:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return uVar3;
}

