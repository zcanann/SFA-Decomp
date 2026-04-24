// Function: FUN_80155b10
// Entry: 80155b10
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x80155cd8) */

void FUN_80155b10(int param_1,int param_2)

{
  char cVar3;
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined4 local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack28;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  cVar3 = FUN_8002e04c();
  if (cVar3 != '\0') {
    local_2c = *(undefined4 *)(param_1 + 0xc);
    local_28 = FLOAT_803e2a48 + *(float *)(param_1 + 0x10);
    local_24 = *(undefined4 *)(param_1 + 0x14);
    iVar1 = *(int *)(param_2 + 0x29c);
    local_38 = *(float *)(iVar1 + 0xc);
    local_34 = FLOAT_803e2a4c + *(float *)(iVar1 + 0x10);
    local_30 = *(float *)(iVar1 + 0x14);
    uStack28 = FUN_800221a0(0xfffffff6,10);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    dVar5 = (double)(FLOAT_803e2a50 *
                    (FLOAT_803e2a58 *
                     (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e2a68) +
                    FLOAT_803e2a54));
    uVar2 = FUN_80169ef4(dVar5,(double)FLOAT_803e2a5c,&local_2c,&local_38,1);
    FUN_80293018(uVar2,&local_40,&local_3c);
    local_3c = (float)((double)local_3c * dVar5);
    local_40 = (float)((double)local_40 * dVar5);
    if (FLOAT_803e2a60 == local_30 - *(float *)(param_1 + 0x14)) {
      local_44 = FLOAT_803e2a60;
    }
    else {
      uVar2 = FUN_800217c0((double)(local_38 - *(float *)(param_1 + 0xc)));
      FUN_80293018(uVar2,&local_48,&local_44);
      local_44 = local_44 * local_3c;
      local_3c = local_3c * local_48;
    }
    iVar1 = FUN_8002bdf4(0x24,0x47b);
    *(undefined4 *)(iVar1 + 8) = local_2c;
    *(float *)(iVar1 + 0xc) = local_28;
    *(undefined4 *)(iVar1 + 0x10) = local_24;
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    iVar1 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (iVar1 != 0) {
      *(float *)(iVar1 + 0x24) = local_3c;
      *(float *)(iVar1 + 0x28) = local_40;
      *(float *)(iVar1 + 0x2c) = local_44;
      *(int *)(iVar1 + 0xc4) = param_1;
      FUN_8000bb18(param_1,0x259);
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

