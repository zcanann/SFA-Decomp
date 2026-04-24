// Function: FUN_80231e30
// Entry: 80231e30
// Size: 776 bytes

void FUN_80231e30(void)

{
  int iVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  double dVar7;
  undefined8 uVar8;
  float local_d8;
  float local_d4;
  float local_d0;
  undefined2 local_cc;
  undefined2 local_ca;
  undefined2 local_c8;
  float local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined auStack180 [68];
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  longlong local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  double local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  uVar8 = FUN_802860dc();
  dVar7 = DOUBLE_803e7180;
  puVar2 = (undefined2 *)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  puVar6 = *(undefined2 **)(iVar3 + 0x13c);
  iVar5 = *(int *)(puVar6 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  uStack108 = (uint)*(ushort *)(iVar3 + 0x14a);
  local_70 = 0x43300000;
  uStack100 = (uint)*(ushort *)(iVar3 + 0x146);
  local_68 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e7180) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e7180));
  local_60 = (longlong)iVar1;
  *(short *)(iVar3 + 0x146) = (short)iVar1;
  uStack84 = (uint)*(ushort *)(iVar3 + 0x14c);
  local_58 = 0x43300000;
  uStack76 = (uint)*(ushort *)(iVar3 + 0x148);
  local_50 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - dVar7) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack76) - dVar7));
  local_48 = (longlong)iVar1;
  *(short *)(iVar3 + 0x148) = (short)iVar1;
  local_c0 = *(undefined4 *)(puVar6 + 6);
  local_bc = *(undefined4 *)(puVar6 + 8);
  local_b8 = *(undefined4 *)(puVar6 + 10);
  local_c4 = FLOAT_803e7188;
  local_cc = *puVar6;
  local_ca = puVar6[1];
  local_c8 = puVar6[2];
  uStack60 = (uint)*(ushort *)(iVar3 + 0x146);
  local_40 = 0x43300000;
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e7194 *
                                        (float)((double)CONCAT44(0x43300000,uStack60) - dVar7)) /
                                       FLOAT_803e7198));
  uStack52 = (int)*(char *)(iVar4 + 0x26) ^ 0x80000000;
  local_38 = 0x43300000;
  local_d8 = FLOAT_803e718c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7178) +
             (float)((double)FLOAT_803e7190 * dVar7);
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x148));
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e7194 * (float)(local_30 - DOUBLE_803e7180)) /
                                       FLOAT_803e7198));
  uStack36 = (int)*(char *)(iVar4 + 0x27) ^ 0x80000000;
  local_28 = 0x43300000;
  local_d4 = FLOAT_803e718c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e7178) +
             (float)((double)FLOAT_803e7190 * dVar7);
  uStack28 = (int)*(char *)(iVar4 + 0x1e) ^ 0x80000000;
  local_20 = 0x43300000;
  local_d0 = FLOAT_803e718c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7178);
  FUN_80021570(&local_cc,auStack180);
  FUN_80247494(auStack180,&local_d8,puVar2 + 6);
  *(undefined4 *)(puVar2 + 0x12) = *(undefined4 *)(puVar6 + 0x12);
  *(undefined4 *)(puVar2 + 0x14) = *(undefined4 *)(puVar6 + 0x14);
  *(undefined4 *)(puVar2 + 0x16) = *(undefined4 *)(puVar6 + 0x16);
  *puVar2 = *puVar6;
  puVar2[1] = puVar6[1];
  if ((*(byte *)(iVar3 + 0x160) >> 3 & 1) == 0) {
    uStack28 = (uint)*(ushort *)(iVar3 + 0x146);
    local_20 = 0x43300000;
    dVar7 = (double)FUN_80293e80((double)((FLOAT_803e7194 *
                                          (float)((double)CONCAT44(0x43300000,uStack28) -
                                                 DOUBLE_803e7180)) / FLOAT_803e7198));
    uStack36 = (int)(short)puVar6[2] ^ 0x80000000;
    local_28 = 0x43300000;
    iVar1 = (int)((double)*(float *)(iVar3 + 0x138) * dVar7 +
                 (double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e7178));
    local_30 = (double)(longlong)iVar1;
    puVar2[2] = (short)iVar1;
  }
  *(byte *)(iVar3 + 0x160) = *(byte *)(iVar5 + 0x160) & 0x80 | *(byte *)(iVar3 + 0x160) & 0x7f;
  if (0 < *(short *)(iVar3 + 0x144)) {
    *(byte *)(iVar3 + 0x160) =
         (byte)((*(byte *)(iVar5 + 0x160) >> 3 & 1) << 3) | *(byte *)(iVar3 + 0x160) & 0xf7;
  }
  if (*(char *)(iVar5 + 0x159) == '\x04') {
    puVar2[3] = puVar2[3] | 0x4000;
    FUN_80035f00(puVar2);
    *(undefined *)(iVar3 + 0x159) = 4;
    *(undefined *)(iVar3 + 0x159) = 4;
  }
  FUN_80286128();
  return;
}

