// Function: FUN_8016a0a0
// Entry: 8016a0a0
// Size: 712 bytes

/* WARNING: Removing unreachable block (ram,0x8016a344) */
/* WARNING: Removing unreachable block (ram,0x8016a33c) */
/* WARNING: Removing unreachable block (ram,0x8016a34c) */

void FUN_8016a0a0(short *param_1)

{
  short sVar2;
  int iVar1;
  undefined4 uVar3;
  undefined8 uVar4;
  undefined8 in_f29;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  int local_58;
  int local_54;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  if (0 < (int)*(uint *)(param_1 + 0x7a)) {
    uStack76 = *(uint *)(param_1 + 0x7a) ^ 0x80000000;
    local_50 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3130) - FLOAT_803db414)
    ;
    local_48 = (longlong)iVar1;
    *(int *)(param_1 + 0x7a) = iVar1;
    if (*(int *)(param_1 + 0x7a) < 1) {
      FUN_8002cbc4();
      goto LAB_8016a33c;
    }
  }
  if (*(char *)(param_1 + 0x1b) != '\0') {
    dVar7 = (double)(*(float *)(param_1 + 0x12) * FLOAT_803db414);
    dVar6 = (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414);
    dVar5 = (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414);
    FUN_8002b95c(dVar7,dVar6,dVar5,param_1);
    *(float *)(param_1 + 0x14) = FLOAT_803e3124 * FLOAT_803db414 + *(float *)(param_1 + 0x14);
    if (*(float *)(param_1 + 0x14) < FLOAT_803e3128) {
      *(float *)(param_1 + 0x14) = FLOAT_803e3128;
    }
    sVar2 = FUN_800217c0(dVar7,dVar5);
    *param_1 = sVar2 + -0x8000;
    uVar4 = FUN_802931a0((double)(float)(dVar7 * dVar7 + (double)(float)(dVar5 * dVar5)));
    sVar2 = FUN_800217c0(uVar4,dVar6);
    param_1[1] = 0x4000 - sVar2;
    FUN_80035df4(param_1,10,1,0);
    FUN_80035f20(param_1);
    if ((*(int *)(*(int *)(param_1 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_8002b9ec(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_8002b9ac(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) == '\0') {
        if (*(float *)(param_1 + 8) < FLOAT_803e312c) {
          FUN_8002cbc4(param_1);
        }
      }
      else {
        *(undefined *)(param_1 + 0x1b) = 0;
        *(undefined4 *)(param_1 + 0x7a) = 0x78;
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
        for (local_58 = 0; local_58 < 0x19; local_58 = local_58 + 1) {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x715,0,1,0xffffffff,&local_58);
        }
        FUN_8000bb18(param_1,0x279);
      }
    }
    else {
      *(undefined *)(param_1 + 0x1b) = 0;
      *(undefined4 *)(param_1 + 0x7a) = 0x78;
      *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
      for (local_54 = 0; local_54 < 0x19; local_54 = local_54 + 1) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x715,0,1,0xffffffff,&local_54);
      }
      FUN_8000bb18(param_1,0x279);
    }
  }
LAB_8016a33c:
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  return;
}

