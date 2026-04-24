// Function: FUN_801f9d9c
// Entry: 801f9d9c
// Size: 1068 bytes

void FUN_801f9d9c(undefined2 *param_1)

{
  char cVar4;
  uint uVar1;
  short sVar3;
  int iVar2;
  int iVar5;
  short *psVar6;
  undefined2 local_48;
  undefined2 local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  double local_30;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  
  iVar5 = *(int *)(param_1 + 0x26);
  psVar6 = *(short **)(param_1 + 0x5c);
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    sVar3 = *(short *)(iVar5 + 0x1a);
    if (sVar3 == 1) {
      iVar5 = FUN_8001ffb4((int)*psVar6);
      if ((iVar5 != 0) || (*psVar6 == -1)) {
        local_30 = (double)(longlong)(int)FLOAT_803db414;
        psVar6[2] = psVar6[2] - (short)(int)FLOAT_803db414;
        if (psVar6[2] < 1) {
          psVar6[2] = psVar6[1];
          iVar5 = FUN_8002bdf4(0x28,0x263);
          *(undefined *)(iVar5 + 6) = 0xff;
          *(undefined *)(iVar5 + 7) = 0xff;
          *(undefined *)(iVar5 + 4) = 2;
          *(undefined *)(iVar5 + 5) = 1;
          uVar1 = FUN_800221a0(-(int)psVar6[4]);
          local_30 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
          *(float *)(iVar5 + 8) = *(float *)(param_1 + 6) + (float)(local_30 - DOUBLE_803e6080);
          *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(param_1 + 8);
          uStack36 = FUN_800221a0(-(int)psVar6[4]);
          uStack36 = uStack36 ^ 0x80000000;
          local_28 = 0x43300000;
          *(float *)(iVar5 + 0x10) =
               *(float *)(param_1 + 10) +
               (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6080);
          *(undefined2 *)(iVar5 + 0x20) = 0x50;
          sVar3 = FUN_800221a0(0,2);
          *(short *)(iVar5 + 0x1e) = sVar3 + 0x16a;
          *(undefined2 *)(iVar5 + 0x22) = 0xffff;
          sVar3 = FUN_800221a0(0xfffffe0c,500);
          *(short *)(iVar5 + 0x18) = sVar3 + 0x5dc;
          sVar3 = FUN_800221a0(0xfffffe0c,500);
          *(short *)(iVar5 + 0x1a) = sVar3 + 0x5dc;
          sVar3 = FUN_800221a0(0xfffffe0c,500);
          *(short *)(iVar5 + 0x1c) = sVar3 + 0x5dc;
          *(undefined *)(iVar5 + 0x24) = 0;
          iVar5 = FUN_8002df90(iVar5,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                               *(undefined4 *)(param_1 + 0x18));
          if (iVar5 != 0) {
            uStack36 = FUN_800221a0(0,10);
            uStack36 = uStack36 ^ 0x80000000;
            local_28 = 0x43300000;
            *(float *)(iVar5 + 0x28) =
                 FLOAT_803e606c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6080) +
                 FLOAT_803e6068;
            uVar1 = FUN_800221a0(0xfffffff6,10);
            local_30 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
            *(float *)(iVar5 + 0x24) = FLOAT_803e6070 * (float)(local_30 - DOUBLE_803e6080);
            uVar1 = FUN_800221a0(0xfffffff6,10);
            local_20 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
            *(float *)(iVar5 + 0x2c) = FLOAT_803e6070 * (float)(local_20 - DOUBLE_803e6080);
          }
        }
      }
    }
    else if ((0 < sVar3) && (sVar3 == 6)) {
      local_20 = (double)(longlong)(int)FLOAT_803db414;
      psVar6[2] = psVar6[2] - (short)(int)FLOAT_803db414;
      if (psVar6[2] < 1) {
        psVar6[2] = psVar6[1];
        iVar2 = FUN_8002bdf4(0x24,0x549);
        *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(iVar5 + 8);
        *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar5 + 0xc);
        *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar5 + 0x10);
        *(undefined *)(iVar2 + 4) = *(undefined *)(iVar5 + 4);
        *(undefined *)(iVar2 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)(iVar2 + 6) = *(undefined *)(iVar5 + 6);
        *(undefined *)(iVar2 + 7) = *(undefined *)(iVar5 + 7);
        *(undefined2 *)(iVar2 + 0x1e) = 0xffff;
        *(undefined2 *)(iVar2 + 0x20) = 0xffff;
        iVar5 = FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                             *(undefined4 *)(param_1 + 0x18));
        if (iVar5 != 0) {
          *(undefined4 *)(iVar5 + 0xf8) = 500;
          local_3c = FLOAT_803e6074;
          *(float *)(iVar5 + 0x28) = FLOAT_803e6074;
          *(float *)(iVar5 + 0x24) = local_3c;
          local_40 = FLOAT_803e6078;
          *(float *)(iVar5 + 0x2c) = FLOAT_803e6078;
          local_38 = local_3c;
          local_34 = local_3c;
          local_44 = 0;
          local_46 = 0;
          local_48 = *param_1;
          FUN_80021ac8(&local_48,iVar5 + 0x24);
          FUN_8000bb18(iVar5,0x10c);
          (**(code **)(*DAT_803dca88 + 8))(iVar5,0x39a,0,0x10002,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(iVar5,0x39b,0,0x10002,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(iVar5,0x39c,0,0x10002,0xffffffff,0);
        }
      }
    }
  }
  return;
}

