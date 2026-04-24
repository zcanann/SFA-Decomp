// Function: FUN_80200ae8
// Entry: 80200ae8
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x80200d60) */
/* WARNING: Removing unreachable block (ram,0x80200af8) */

undefined4 FUN_80200ae8(double param_1,ushort *param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  short *psVar6;
  int iVar7;
  double dVar8;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  iVar4 = *(int *)(param_2 + 0x5c);
  iVar7 = *(int *)(iVar4 + 0x40c);
  bVar1 = *(byte *)(iVar4 + 0x406);
  *(byte *)(iVar7 + 0x14) = *(byte *)(iVar7 + 0x14) | 2;
  *(byte *)(iVar7 + 0x15) = *(byte *)(iVar7 + 0x15) & 0xfb;
  fVar2 = FLOAT_803e6f40;
  if ((*(ushort *)(*(int *)(param_3 + 0x2d0) + 0xb0) & 0x1000) == 0) {
    uStack_24 = (uint)*(byte *)(iVar4 + 0x406);
    local_28 = 0x43300000;
    FUN_802032b0((double)FLOAT_803e6f60,
                 (double)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e6f78) /
                         FLOAT_803e6f5c),(double)FLOAT_803e6f64,param_1,param_2,
                 *(int *)(param_3 + 0x2d0));
    if ((*(byte *)(iVar7 + 0x44) >> 5 & 1) != 0) {
      FUN_80203064(param_2,&DAT_8032a37c,(float *)&DAT_8032a38c,4);
    }
    dVar8 = (double)FUN_80021754((float *)(param_2 + 0xc),
                                 (float *)(*(int *)(param_3 + 0x2d0) + 0x18));
    *(undefined *)(param_3 + 0x34d) = 1;
    fVar2 = FLOAT_803e6f6c;
    if ((double)FLOAT_803e6f68 <= dVar8) {
      if (((double)FLOAT_803e6f70 <= dVar8) ||
         (uVar3 = FUN_80022264(0,8000 / bVar1), fVar2 = FLOAT_803e6f40, uVar3 != 0)) {
        FUN_8002f6cc((double)*(float *)(param_3 + 0x280),(int)param_2,(float *)(param_3 + 0x2a0));
      }
      else {
        *(float *)(param_3 + 0x280) = FLOAT_803e6f40;
        *(float *)(param_3 + 0x284) = fVar2;
        uVar5 = *(undefined4 *)(param_3 + 0x2d0);
        local_44 = *(undefined4 *)(iVar7 + 0x30);
        local_48 = *(undefined4 *)(iVar7 + 0x2c);
        psVar6 = *(short **)(iVar7 + 0x24);
        local_4c = *(undefined4 *)(iVar7 + 0x28);
        uVar3 = FUN_800138e4(psVar6);
        if (uVar3 == 0) {
          FUN_80013978(psVar6,(uint)&local_4c);
        }
        psVar6 = *(short **)(iVar7 + 0x24);
        local_58 = 4;
        local_54 = 1;
        local_50 = uVar5;
        uVar3 = FUN_800138e4(psVar6);
        if (uVar3 == 0) {
          FUN_80013978(psVar6,(uint)&local_58);
        }
        *(undefined *)(iVar7 + 0x34) = 1;
      }
    }
    else {
      *(float *)(param_3 + 0x280) = *(float *)(param_3 + 0x280) * FLOAT_803e6f6c;
      *(float *)(param_3 + 0x284) = *(float *)(param_3 + 0x284) * fVar2;
      uVar5 = *(undefined4 *)(param_3 + 0x2d0);
      local_2c = *(undefined4 *)(iVar7 + 0x30);
      local_30 = *(undefined4 *)(iVar7 + 0x2c);
      psVar6 = *(short **)(iVar7 + 0x24);
      local_34 = *(undefined4 *)(iVar7 + 0x28);
      uVar3 = FUN_800138e4(psVar6);
      if (uVar3 == 0) {
        FUN_80013978(psVar6,(uint)&local_34);
      }
      psVar6 = *(short **)(iVar7 + 0x24);
      local_40 = 2;
      local_3c = 1;
      local_38 = uVar5;
      uVar3 = FUN_800138e4(psVar6);
      if (uVar3 == 0) {
        FUN_80013978(psVar6,(uint)&local_40);
      }
      *(undefined *)(iVar7 + 0x34) = 1;
    }
  }
  else {
    *(float *)(param_3 + 0x280) = FLOAT_803e6f40;
    *(float *)(param_3 + 0x284) = fVar2;
    *(float *)(param_3 + 0x2a0) = FLOAT_803e6f58;
  }
  return 0;
}

