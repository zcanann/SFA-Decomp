// Function: FUN_802974a0
// Entry: 802974a0
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x80297724) */

undefined4 FUN_802974a0(double param_1,int param_2,uint *param_3)

{
  short sVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_2 + 0xb8);
  *(float *)(iVar5 + 0x778) = FLOAT_803e7ed8;
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x2000000;
  *param_3 = *param_3 | 0x200000;
  if (FLOAT_803e7ea4 == *(float *)(iVar5 + 0x784)) {
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0x7f;
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xef;
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xf7;
    FUN_80170380(DAT_803de450,2);
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfd;
    *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
    FUN_80035ea4(param_2);
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xbf;
    *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfb | 4;
    *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xef;
    *(undefined *)(iVar5 + 0x800) = 0;
    if (*(int *)(iVar5 + 0x7f8) != 0) {
      sVar1 = *(short *)(*(int *)(iVar5 + 0x7f8) + 0x46);
      if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
        FUN_80182504();
      }
      else {
        FUN_800ea774();
      }
      *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(iVar5 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(iVar5 + 0x7f8) = 0;
    }
    param_3[0xc2] = (uint)FUN_802a514c;
    uVar4 = 3;
  }
  else {
    if (*(char *)((int)param_3 + 0x27a) != '\0') {
      FUN_80030334(param_2,0x12,1);
    }
    fVar2 = (FLOAT_803e7ee0 + *(float *)(iVar5 + 0x784)) * FLOAT_803e7e98;
    fVar3 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar2) && (fVar3 = fVar2, FLOAT_803e7ee0 < fVar2)) {
      fVar3 = FLOAT_803e7ee0;
    }
    FUN_80030304((double)(FLOAT_803e7ee0 - fVar3),param_2);
    (**(code **)(*DAT_803dca8c + 0x44))
              (param_1,(double)FLOAT_803e7ee0,param_2,param_3,*(undefined4 *)(iVar5 + 0x474));
    param_3[0xae] = (uint)FLOAT_803e7ef4;
    param_3[0xa8] = (uint)FLOAT_803e7ef8;
    *(float *)(param_2 + 0x28) = (float)((double)*(float *)(iVar5 + 0x784) * param_1);
    if (FLOAT_803e7efc < (float)param_3[0xa6]) {
      *(short *)(iVar5 + 0x478) =
           (short)(int)(FLOAT_803e7f00 *
                        (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 *(uint *)(iVar5 + 0x480) ^
                                                                 0x80000000) - DOUBLE_803e7ec0) *
                               param_1) * FLOAT_803e7f04 +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(iVar5 + 0x478) ^ 0x80000000) -
                              DOUBLE_803e7ec0));
      *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
    }
    FUN_802abae8((double)FLOAT_803e7ea4,param_2,param_3,iVar5);
    uVar4 = 0;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return uVar4;
}

