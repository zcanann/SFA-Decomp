// Function: FUN_800972dc
// Entry: 800972dc
// Size: 1112 bytes

/* WARNING: Removing unreachable block (ram,0x8009770c) */
/* WARNING: Removing unreachable block (ram,0x80097714) */

void FUN_800972dc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,uint param_6,uint param_7,int param_8,uint param_9)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  double extraout_f1;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  undefined8 uVar6;
  undefined2 local_c8;
  undefined2 local_c6;
  undefined2 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined2 local_80;
  undefined2 local_7c;
  undefined2 local_7a;
  undefined2 local_78;
  undefined2 local_76;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined4 local_60;
  uint uStack92;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar6 = FUN_802860c4();
  local_90 = DAT_802c20a8;
  local_8c = DAT_802c20ac;
  local_88 = DAT_802c20b0;
  local_84 = DAT_802c20b4;
  local_80 = DAT_802c20b8;
  local_a0 = DAT_802c20bc;
  local_9c = DAT_802c20c0;
  local_98 = DAT_802c20c4;
  local_94 = DAT_802c20c8;
  local_b0 = DAT_802c20cc;
  local_ac = DAT_802c20d0;
  local_a8 = DAT_802c20d4;
  local_a4 = DAT_802c20d8;
  local_c0 = DAT_802c20dc;
  local_bc = DAT_802c20e0;
  local_b8 = DAT_802c20e4;
  local_b4 = DAT_802c20e8;
  local_74 = (float)extraout_f1;
  local_76 = *(undefined2 *)((int)&local_90 + (param_5 & 0xff) * 2);
  local_7a = 0x3c;
  iVar3 = 0;
  iVar1 = ((uint)uVar6 & 0xff) * 2;
  do {
    iVar2 = FUN_800221a0(0,99);
    if (iVar2 < (int)(param_7 & 0xff)) {
      uStack92 = FUN_800221a0(0,1000);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar5 = (double)((float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df360) /
                      FLOAT_803df368);
      switch(param_6 & 0xff) {
      case 1:
        local_c8 = FUN_800221a0(0,0xffff);
        local_c6 = FUN_800221a0(0,0xffff);
        local_c4 = FUN_800221a0(0,0xffff);
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar5 * (double)(float)(dVar5 * dVar5) -
                                          (double)FLOAT_803df354));
        break;
      case 2:
        local_c8 = 0;
        local_c6 = FUN_800221a0(0,0xffff);
        local_c4 = 0;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar5 * (double)(float)(dVar5 * dVar5) -
                                          (double)FLOAT_803df354));
        break;
      case 3:
        local_c8 = FUN_800221a0(0,0xffff);
        local_c6 = 0;
        local_c4 = 0;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar5 * (double)(float)(dVar5 * dVar5) -
                                          (double)FLOAT_803df354));
        break;
      case 4:
        local_c8 = 0;
        local_c6 = 0;
        local_c4 = FUN_800221a0(0,0xffff);
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar5 * (double)(float)(dVar5 * dVar5) -
                                          (double)FLOAT_803df354));
        break;
      case 5:
        local_c8 = FUN_800221a0(0x7fff,0xffff);
        local_c6 = 0;
        local_c4 = FUN_800221a0(0,0xffff);
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar5 * (double)(float)(dVar5 * dVar5) -
                                          (double)FLOAT_803df354));
        break;
      case 6:
        local_c8 = FUN_800221a0(0,0xffff);
        local_c6 = FUN_800221a0(0,0xffff);
        local_c4 = FUN_800221a0(0,0xffff);
        local_70 = (float)(dVar5 * param_2);
        break;
      case 7:
        local_c8 = FUN_800221a0(0,0xffff);
        local_c6 = FUN_800221a0(0,0xffff);
        local_c4 = FUN_800221a0(0,0xffff);
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar5 * (double)(float)(dVar5 * (double)(float)(dVar5 * (
                                                  double)(float)(dVar5 * dVar5))) -
                                          (double)FLOAT_803df354));
      }
      local_6c = FLOAT_803df35c;
      local_68 = FLOAT_803df35c;
      FUN_80021ac8(&local_c8,&local_70);
      if (param_8 != 0) {
        local_70 = local_70 + *(float *)(param_8 + 0xc);
        local_6c = local_6c + *(float *)(param_8 + 0x10);
        local_68 = local_68 + *(float *)(param_8 + 0x14);
      }
      local_78 = *(undefined2 *)((int)&local_b0 + iVar1);
      local_7c = *(undefined2 *)((int)&local_c0 + iVar1);
      (**(code **)(*DAT_803dca88 + 8))
                ((int)((ulonglong)uVar6 >> 0x20),*(undefined2 *)((int)&local_a0 + iVar1),&local_7c,
                 param_9 | 2,0xffffffff,0);
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  FUN_80286110();
  return;
}

