// Function: FUN_80062498
// Entry: 80062498
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x800626a8) */

void FUN_80062498(void)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  float *pfVar6;
  undefined4 uVar7;
  double in_f31;
  undefined8 uVar8;
  undefined4 local_218;
  uint *local_214;
  undefined auStack528 [4];
  undefined4 local_20c;
  undefined4 local_208;
  float local_204;
  undefined4 local_200;
  float local_1fc;
  float local_1f8;
  float local_1f4;
  undefined auStack496 [24];
  undefined auStack472 [96];
  undefined auStack376 [304];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  uVar8 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  local_20c = 0;
  local_218 = 0;
  uVar4 = FUN_80022a48();
  pfVar6 = *(float **)(iVar3 + 100);
  iVar5 = FUN_8005cdbc();
  if (iVar5 == 0) {
    *(undefined4 *)(*(int *)(iVar3 + 100) + 0xc) = 0;
  }
  else {
    if ((pfVar6[4] == 0.0) || (pfVar6[4] == -NAN)) {
      local_1fc = pfVar6[5];
      local_1f8 = pfVar6[6];
      local_1f4 = pfVar6[7];
      FUN_80061094((double)pfVar6[0xb],&local_1fc,auStack472);
      fVar1 = FLOAT_803dec58;
      if (*(int *)(iVar3 + 0x54) != 0) {
        uStack68 = (int)*(short *)(*(int *)(iVar3 + 0x54) + 0x5e) / 2 ^ 0x80000000;
        local_48 = 0x43300000;
        fVar1 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dec60);
      }
      in_f31 = (double)fVar1;
      local_208 = *(undefined4 *)(iVar3 + 0x18);
      local_204 = (float)((double)*(float *)(iVar3 + 0x1c) + in_f31);
      local_200 = *(undefined4 *)(iVar3 + 0x20);
      FUN_800611d4((double)*pfVar6,auStack472,&local_208,auStack496);
      FUN_800691c0(iVar3,auStack496,0x81,0);
      FUN_80069958(&local_214);
      FUN_80069968(&local_20c,&local_218);
      uVar2 = local_218;
      uStack60 = *local_214 ^ 0x80000000;
      local_40 = 0x43300000;
      uStack52 = local_214[2] ^ 0x80000000;
      local_38 = 0x43300000;
      local_20c = FUN_80060c14((double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                              DOUBLE_803dec60),
                               (double)(float)((double)CONCAT44(0x43300000,uStack52) -
                                              DOUBLE_803dec60),iVar3,local_218,&DAT_803879bc,
                               DAT_803dcf2c,local_20c,(int)uVar8,(uint)pfVar6[0xc] & 0x40000);
      DAT_803dcee0 = uVar2;
      DAT_803dcef0 = (undefined2)local_20c;
      DAT_803dcee4 = local_214;
      FUN_80061954(iVar3,auStack472,auStack376);
      FUN_80061dd8(iVar3,auStack472,auStack376,local_20c,DAT_803dcf2c,uVar4,&DAT_803879bc,0x555);
    }
    FUN_80061f0c(in_f31,uVar4,pfVar6,iVar3,(int)DAT_803dcef2,auStack528,auStack472);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128(0);
  return;
}

