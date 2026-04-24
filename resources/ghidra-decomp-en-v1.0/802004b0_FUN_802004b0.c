// Function: FUN_802004b0
// Entry: 802004b0
// Size: 672 bytes

/* WARNING: Removing unreachable block (ram,0x80200728) */

undefined4 FUN_802004b0(undefined8 param_1,int param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  double dVar7;
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
  uint uStack36;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_2 + 0xb8);
  iVar5 = *(int *)(iVar3 + 0x40c);
  bVar1 = *(byte *)(iVar3 + 0x406);
  *(byte *)(iVar5 + 0x14) = *(byte *)(iVar5 + 0x14) | 2;
  *(byte *)(iVar5 + 0x15) = *(byte *)(iVar5 + 0x15) & 0xfb;
  fVar2 = FLOAT_803e62a8;
  if ((*(ushort *)(*(int *)(param_3 + 0x2d0) + 0xb0) & 0x1000) == 0) {
    uStack36 = (uint)*(byte *)(iVar3 + 0x406);
    local_28 = 0x43300000;
    dVar7 = (double)((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e62e0) /
                    FLOAT_803e62c4);
    FUN_80202c78((double)FLOAT_803e62c8,dVar7,(double)FLOAT_803e62cc,param_1);
    if ((*(byte *)(iVar5 + 0x44) >> 5 & 1) != 0) {
      FUN_80202a2c(dVar7,param_2,&DAT_8032973c,&DAT_8032974c,4);
    }
    dVar7 = (double)FUN_80021690(param_2 + 0x18,*(int *)(param_3 + 0x2d0) + 0x18);
    *(undefined *)(param_3 + 0x34d) = 1;
    fVar2 = FLOAT_803e62d4;
    if ((double)FLOAT_803e62d0 <= dVar7) {
      if (((double)FLOAT_803e62d8 <= dVar7) ||
         (iVar3 = FUN_800221a0(0,8000 / bVar1), fVar2 = FLOAT_803e62a8, iVar3 != 0)) {
        FUN_8002f5d4((double)*(float *)(param_3 + 0x280),param_2,param_3 + 0x2a0);
      }
      else {
        *(float *)(param_3 + 0x280) = FLOAT_803e62a8;
        *(float *)(param_3 + 0x284) = fVar2;
        local_50 = *(undefined4 *)(param_3 + 0x2d0);
        local_44 = *(undefined4 *)(iVar5 + 0x30);
        local_48 = *(undefined4 *)(iVar5 + 0x2c);
        uVar4 = *(undefined4 *)(iVar5 + 0x24);
        local_4c = *(undefined4 *)(iVar5 + 0x28);
        iVar3 = FUN_800138c4(uVar4);
        if (iVar3 == 0) {
          FUN_80013958(uVar4,&local_4c);
        }
        uVar4 = *(undefined4 *)(iVar5 + 0x24);
        local_58 = 4;
        local_54 = 1;
        iVar3 = FUN_800138c4(uVar4);
        if (iVar3 == 0) {
          FUN_80013958(uVar4,&local_58);
        }
        *(undefined *)(iVar5 + 0x34) = 1;
      }
    }
    else {
      *(float *)(param_3 + 0x280) = *(float *)(param_3 + 0x280) * FLOAT_803e62d4;
      *(float *)(param_3 + 0x284) = *(float *)(param_3 + 0x284) * fVar2;
      local_38 = *(undefined4 *)(param_3 + 0x2d0);
      local_2c = *(undefined4 *)(iVar5 + 0x30);
      local_30 = *(undefined4 *)(iVar5 + 0x2c);
      uVar4 = *(undefined4 *)(iVar5 + 0x24);
      local_34 = *(undefined4 *)(iVar5 + 0x28);
      iVar3 = FUN_800138c4(uVar4);
      if (iVar3 == 0) {
        FUN_80013958(uVar4,&local_34);
      }
      uVar4 = *(undefined4 *)(iVar5 + 0x24);
      local_40 = 2;
      local_3c = 1;
      iVar3 = FUN_800138c4(uVar4);
      if (iVar3 == 0) {
        FUN_80013958(uVar4,&local_40);
      }
      *(undefined *)(iVar5 + 0x34) = 1;
    }
  }
  else {
    *(float *)(param_3 + 0x280) = FLOAT_803e62a8;
    *(float *)(param_3 + 0x284) = fVar2;
    *(float *)(param_3 + 0x2a0) = FLOAT_803e62c0;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return 0;
}

