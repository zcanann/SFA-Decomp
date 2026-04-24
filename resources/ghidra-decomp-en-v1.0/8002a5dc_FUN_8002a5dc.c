// Function: FUN_8002a5dc
// Entry: 8002a5dc
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x8002a750) */
/* WARNING: Removing unreachable block (ram,0x8002a748) */
/* WARNING: Removing unreachable block (ram,0x8002a758) */

void FUN_8002a5dc(int param_1)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f29;
  double dVar4;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  undefined auStack200 [12];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  undefined auStack164 [16];
  float local_94;
  undefined4 local_90;
  undefined4 local_8c;
  float local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined auStack116 [12];
  float local_68;
  float local_58;
  float local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  fVar1 = FLOAT_803de888 * *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
  dVar4 = (double)(((*(float *)(param_1 + 0x88) - FLOAT_803dcecc) -
                   (*(float *)(param_1 + 0x14) - FLOAT_803dcddc)) / fVar1);
  dVar5 = (double)(((*(float *)(param_1 + 0xc) - FLOAT_803dced0) -
                   (*(float *)(param_1 + 0x80) - FLOAT_803dcdd8)) / fVar1);
  if (FLOAT_803de88c < (float)(dVar5 * dVar5 + (double)(float)(dVar4 * dVar4))) {
    dVar3 = (double)FUN_802931a0();
    local_b0 = (float)(dVar5 / dVar3);
    local_ac = FLOAT_803de88c;
    local_a8 = (float)(-dVar4 / dVar3);
    local_bc = FLOAT_803de88c;
    local_b8 = FLOAT_803de890;
    local_b4 = FLOAT_803de88c;
    FUN_8024784c(&local_b0,&local_bc,auStack200);
    FUN_802471e0((double)(FLOAT_803de894 * (float)((double)FLOAT_803de898 * -dVar3)),auStack164,
                 auStack200);
    FUN_80021570(param_1,auStack116);
    local_68 = FLOAT_803de88c;
    local_58 = FLOAT_803de88c;
    local_48 = FLOAT_803de88c;
    FUN_80246eb4(auStack164,auStack116,auStack164);
    local_b0 = local_84;
    local_ac = (float)local_80;
    local_a8 = (float)local_7c;
    local_bc = local_94;
    local_b8 = (float)local_90;
    local_b4 = (float)local_8c;
    FUN_800213d0(&local_b0,&local_bc,param_1 + 4,param_1 + 2,param_1);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  return;
}

