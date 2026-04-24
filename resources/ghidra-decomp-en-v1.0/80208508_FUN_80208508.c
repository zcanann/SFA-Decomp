// Function: FUN_80208508
// Entry: 80208508
// Size: 344 bytes

/* WARNING: Removing unreachable block (ram,0x80208630) */
/* WARNING: Removing unreachable block (ram,0x80208638) */

void FUN_80208508(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  float local_90;
  float local_8c;
  float local_88;
  undefined auStack132 [84];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar3 = 0;
  iVar4 = param_2;
  do {
    if (*(char *)(param_2 + 0x68) <= iVar3) {
LAB_80208630:
      __psq_l0(auStack8,uVar5);
      __psq_l1(auStack8,uVar5);
      __psq_l0(auStack24,uVar5);
      __psq_l1(auStack24,uVar5);
      return;
    }
    local_90 = *(float *)(iVar4 + 4) + *(float *)(param_1 + 0xc);
    dVar6 = (double)local_90;
    local_8c = *(float *)(iVar4 + 8) + *(float *)(param_1 + 0x10);
    local_88 = *(float *)(iVar4 + 0xc) + *(float *)(param_1 + 0x14);
    dVar7 = (double)local_88;
    iVar2 = FUN_800640cc((double)FLOAT_803e6488,param_1 + 0xc,&local_90,1,auStack132,param_1,8,
                         0xffffffff,0,0);
    if (iVar2 != 0) {
      if (FLOAT_803e648c != *(float *)(param_1 + 0x24)) {
        *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + (float)((double)local_90 - dVar6);
      }
      if (FLOAT_803e648c != *(float *)(param_1 + 0x2c)) {
        *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + (float)((double)local_88 - dVar7);
      }
      fVar1 = FLOAT_803e648c;
      *(float *)(param_1 + 0x24) = FLOAT_803e648c;
      *(float *)(param_1 + 0x28) = fVar1;
      *(float *)(param_1 + 0x2c) = fVar1;
      FUN_8000bb18(param_1,0x1d0);
      goto LAB_80208630;
    }
    iVar4 = iVar4 + 0xc;
    iVar3 = iVar3 + 1;
  } while( true );
}

