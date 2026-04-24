// Function: FUN_801afffc
// Entry: 801afffc
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x801b028c) */
/* WARNING: Removing unreachable block (ram,0x801b0294) */

void FUN_801afffc(short *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined2 local_6c;
  undefined2 local_6a;
  undefined2 local_68;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if (param_1[0x23] == 0x1fa) {
    local_78 = DAT_802c2318;
    local_74 = DAT_802c231c;
    local_70 = DAT_802c2320;
    local_68 = 0;
    local_6a = FUN_800221a0(0xffffd120,12000);
    local_6c = FUN_800221a0(0,0xfffe);
    FUN_80021ac8(&local_6c,&local_78);
    *(undefined4 *)(param_1 + 0x7a) = 0x4b;
    *(undefined4 *)(param_1 + 0x12) = local_78;
    *(undefined4 *)(param_1 + 0x14) = local_74;
    *(undefined4 *)(param_1 + 0x16) = local_70;
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * FLOAT_803e47d4;
  }
  else {
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    dVar5 = DOUBLE_803e47e8;
    puVar3 = *(undefined4 **)(param_1 + 0x5c);
    uStack76 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar7 = (double)(FLOAT_803e47d8 *
                    (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e47e8));
    uStack68 = (int)*(short *)(param_2 + 0x1c) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar6 = (double)(FLOAT_803e47d8 *
                    (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e47e8));
    puVar3[2] = *(undefined4 *)(param_1 + 8);
    puVar3[3] = *(undefined4 *)(param_2 + 0x14);
    *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
    uStack60 = (int)*param_1 ^ 0x80000000;
    local_40 = 0x43300000;
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e47dc *
                                          (float)((double)CONCAT44(0x43300000,uStack60) - dVar5)) /
                                         FLOAT_803e47e0));
    *(float *)(param_1 + 0x12) = (float)(dVar6 * -dVar5);
    *(float *)(param_1 + 0x14) = (float)dVar7;
    uStack52 = (int)*param_1 ^ 0x80000000;
    local_38 = 0x43300000;
    dVar5 = (double)FUN_80294204((double)((FLOAT_803e47dc *
                                          (float)((double)CONCAT44(0x43300000,uStack52) -
                                                 DOUBLE_803e47e8)) / FLOAT_803e47e0));
    *(float *)(param_1 + 0x16) = (float)(dVar6 * -dVar5);
    if (*(int *)(param_1 + 0x2a) != 0) {
      *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6a) = 0;
    }
    iVar1 = *(int *)(param_1 + 0x32);
    if (iVar1 != 0) {
      *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x810;
    }
    uVar2 = FUN_8002e0b4(puVar3[3]);
    *puVar3 = uVar2;
    *(byte *)(puVar3 + 4) = *(byte *)(puVar3 + 4) | 0x10;
    FUN_80035f00(param_1);
    param_1[0x58] = param_1[0x58] | 0x2000;
    uVar2 = FUN_8001f4c8(param_1,1);
    puVar3[1] = uVar2;
    if (puVar3[1] != 0) {
      FUN_8001db2c(puVar3[1],2);
      FUN_8001daf0(puVar3[1],0xff,0x80,0,0);
      FUN_8001dc38((double)FLOAT_803e4800,(double)FLOAT_803e4804,puVar3[1]);
      FUN_8001d730((double)FLOAT_803e4808,puVar3[1],0,0xff,0x80,0,100);
      FUN_8001d714((double)FLOAT_803e4808,puVar3[1]);
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return;
}

