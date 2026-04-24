// Function: FUN_8020dbc4
// Entry: 8020dbc4
// Size: 332 bytes

/* WARNING: Removing unreachable block (ram,0x8020dce8) */
/* WARNING: Removing unreachable block (ram,0x8020dcf0) */

void FUN_8020dbc4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f30;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  undefined8 uVar5;
  undefined2 local_88;
  undefined2 local_86;
  undefined2 local_84;
  float local_80;
  float local_7c;
  float local_78;
  undefined auStack116 [6];
  undefined2 local_6e;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar5 = FUN_802860cc();
  dVar3 = (double)FLOAT_803e665c;
  dVar4 = DOUBLE_803e6670;
  for (iVar1 = 0; iVar1 < param_6; iVar1 = iVar1 + 1) {
    local_80 = (float)dVar3;
    uStack84 = FUN_800221a0((int)uVar5,param_3);
    uStack84 = uStack84 ^ 0x80000000;
    local_58 = 0x43300000;
    local_7c = (float)((double)CONCAT44(0x43300000,uStack84) - dVar4);
    uStack76 = FUN_800221a0(param_4,param_5);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_78 = (float)((double)CONCAT44(0x43300000,uStack76) - dVar4);
    local_88 = 0;
    local_86 = 0;
    local_84 = FUN_800221a0(0xffff8001,0x7fff);
    FUN_80021ac8(&local_88,&local_80);
    local_68 = local_80;
    local_64 = local_7c;
    local_60 = local_78;
    local_6e = 100;
    (**(code **)(*DAT_803dca88 + 8))
              ((int)((ulonglong)uVar5 >> 0x20),param_7,auStack116,2,0xffffffff,0);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  FUN_80286118();
  return;
}

