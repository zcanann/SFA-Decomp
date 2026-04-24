// Function: FUN_80297c00
// Entry: 80297c00
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x80297e84) */
/* WARNING: Removing unreachable block (ram,0x80297c10) */

undefined4
FUN_80297c00(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  *(float *)(iVar5 + 0x778) = FLOAT_803e8b70;
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x2000000;
  *param_10 = *param_10 | 0x200000;
  if ((double)FLOAT_803e8b3c == (double)*(float *)(iVar5 + 0x784)) {
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0x7f;
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xef;
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xf7;
    FUN_8017082c();
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfd;
    *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
    FUN_80035f9c(param_9);
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xbf;
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfb | 4;
    *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xef;
    *(undefined *)(iVar5 + 0x800) = 0;
    iVar3 = *(int *)(iVar5 + 0x7f8);
    if (iVar3 != 0) {
      if ((*(short *)(iVar3 + 0x46) == 0x3cf) || (*(short *)(iVar3 + 0x46) == 0x662)) {
        FUN_80182a5c(iVar3);
      }
      else {
        FUN_800ea9f8(iVar3);
      }
      *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(iVar5 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(iVar5 + 0x7f8) = 0;
    }
    param_10[0xc2] = (uint)FUN_802a58ac;
    uVar4 = 3;
  }
  else {
    if (*(char *)((int)param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x12,1,param_12,param_13,param_14,param_15,param_16);
    }
    fVar2 = (FLOAT_803e8b78 + *(float *)(iVar5 + 0x784)) * FLOAT_803e8b30;
    fVar1 = FLOAT_803e8b3c;
    if ((FLOAT_803e8b3c <= fVar2) && (fVar1 = fVar2, FLOAT_803e8b78 < fVar2)) {
      fVar1 = FLOAT_803e8b78;
    }
    FUN_800303fc((double)(FLOAT_803e8b78 - fVar1),param_9);
    (**(code **)(*DAT_803dd70c + 0x44))
              (param_1,(double)FLOAT_803e8b78,param_9,param_10,*(undefined4 *)(iVar5 + 0x474));
    param_10[0xae] = (uint)FLOAT_803e8b8c;
    param_10[0xa8] = (uint)FLOAT_803e8b90;
    *(float *)(param_9 + 0x28) = (float)((double)*(float *)(iVar5 + 0x784) * param_1);
    if (FLOAT_803e8b94 < (float)param_10[0xa6]) {
      *(short *)(iVar5 + 0x478) =
           (short)(int)(FLOAT_803e8b98 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 *(uint *)(iVar5 + 0x480) ^
                                                                 0x80000000) - DOUBLE_803e8b58) *
                               param_1) * FLOAT_803e8b9c +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(iVar5 + 0x478) ^ 0x80000000) -
                              DOUBLE_803e8b58));
      *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
    }
    FUN_802ac248((double)FLOAT_803e8b3c,param_9,(int)param_10,iVar5);
    uVar4 = 0;
  }
  return uVar4;
}

