// Function: FUN_801eb420
// Entry: 801eb420
// Size: 532 bytes

/* WARNING: Removing unreachable block (ram,0x801eb604) */
/* WARNING: Removing unreachable block (ram,0x801eb5fc) */
/* WARNING: Removing unreachable block (ram,0x801eb60c) */

undefined4 FUN_801eb420(short *param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f29;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  short local_a8;
  undefined2 local_a6;
  undefined2 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  undefined auStack144 [64];
  longlong local_50;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar3 = *(int *)(param_1 + 0x5c);
  *(code **)(param_3 + 0xe8) = FUN_801eb334;
  FUN_80035f00();
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 3) {
      (**(code **)(*DAT_803dca68 + 0x60))();
    }
    else if ((((bVar1 < 3) && (1 < bVar1)) && (param_1[0x23] != 0x16c)) && (param_1[0x23] != 0x16f))
    {
      FUN_800200e8(0x499,1);
    }
  }
  if (*(char *)(iVar3 + 0x421) == '\x02') {
    dVar5 = (double)FLOAT_803db418;
    dVar8 = (double)(float)(dVar5 * (double)(*(float *)(param_1 + 6) - *(float *)(iVar3 + 0x16c)));
    dVar7 = (double)(float)(dVar5 * (double)(*(float *)(param_1 + 8) - *(float *)(iVar3 + 0x170)));
    dVar6 = (double)(float)(dVar5 * (double)(float)((double)*(float *)(param_1 + 10) -
                                                   (double)*(float *)(iVar3 + 0x174)));
    local_9c = FLOAT_803e5ae8;
    local_98 = FLOAT_803e5ae8;
    local_94 = FLOAT_803e5ae8;
    local_a0 = FLOAT_803e5aec;
    local_a8 = -*param_1;
    local_a6 = 0;
    local_a4 = 0;
    FUN_80021ba0((double)*(float *)(param_1 + 10),dVar5,auStack144,&local_a8);
    FUN_800226cc(dVar8,dVar7,dVar6,auStack144,iVar3 + 0x494,iVar3 + 0x498,iVar3 + 0x49c);
    *(char *)(iVar3 + 0x460) = *(char *)(iVar3 + 0x460) + DAT_803db410 * '\b';
    if ('F' < *(char *)(iVar3 + 0x460)) {
      *(undefined *)(iVar3 + 0x460) = 0x46;
    }
    iVar2 = (int)(FLOAT_803e5ba0 * -*(float *)(iVar3 + 0x430));
    local_50 = (longlong)iVar2;
    FUN_801ea240((double)*(float *)(iVar3 + 0x49c),param_1,iVar3,iVar2,iVar3 + 0x461,4);
  }
  *(byte *)(iVar3 + 0x428) = *(byte *)(iVar3 + 0x428) & 0xf7;
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return 0;
}

