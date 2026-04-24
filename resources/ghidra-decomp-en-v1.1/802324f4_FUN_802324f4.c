// Function: FUN_802324f4
// Entry: 802324f4
// Size: 776 bytes

void FUN_802324f4(void)

{
  int iVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  ushort *puVar6;
  double dVar7;
  undefined8 uVar8;
  float local_d8;
  float local_d4;
  float local_d0;
  ushort local_cc;
  ushort local_ca;
  ushort local_c8;
  float local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  float afStack_b4 [17];
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  longlong local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar8 = FUN_80286840();
  dVar7 = DOUBLE_803e7e18;
  puVar2 = (ushort *)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  puVar6 = *(ushort **)(iVar3 + 0x13c);
  iVar5 = *(int *)(puVar6 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  uStack_6c = (uint)*(ushort *)(iVar3 + 0x14a);
  local_70 = 0x43300000;
  uStack_64 = (uint)*(ushort *)(iVar3 + 0x146);
  local_68 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e7e18) * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e7e18));
  local_60 = (longlong)iVar1;
  *(short *)(iVar3 + 0x146) = (short)iVar1;
  uStack_54 = (uint)*(ushort *)(iVar3 + 0x14c);
  local_58 = 0x43300000;
  uStack_4c = (uint)*(ushort *)(iVar3 + 0x148);
  local_50 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - dVar7) * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_4c) - dVar7));
  local_48 = (longlong)iVar1;
  *(short *)(iVar3 + 0x148) = (short)iVar1;
  local_c0 = *(undefined4 *)(puVar6 + 6);
  local_bc = *(undefined4 *)(puVar6 + 8);
  local_b8 = *(undefined4 *)(puVar6 + 10);
  local_c4 = FLOAT_803e7e20;
  local_cc = *puVar6;
  local_ca = puVar6[1];
  local_c8 = puVar6[2];
  uStack_3c = (uint)*(ushort *)(iVar3 + 0x146);
  local_40 = 0x43300000;
  dVar7 = (double)FUN_802945e0();
  uStack_34 = (int)*(char *)(iVar4 + 0x26) ^ 0x80000000;
  local_38 = 0x43300000;
  local_d8 = FLOAT_803e7e24 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e7e10) +
             (float)((double)FLOAT_803e7e28 * dVar7);
  local_30 = CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x148));
  dVar7 = (double)FUN_802945e0();
  uStack_24 = (int)*(char *)(iVar4 + 0x27) ^ 0x80000000;
  local_28 = 0x43300000;
  local_d4 = FLOAT_803e7e24 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7e10) +
             (float)((double)FLOAT_803e7e28 * dVar7);
  uStack_1c = (int)*(char *)(iVar4 + 0x1e) ^ 0x80000000;
  local_20 = 0x43300000;
  local_d0 = FLOAT_803e7e24 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7e10);
  FUN_80021634(&local_cc,afStack_b4);
  FUN_80247bf8(afStack_b4,&local_d8,(float *)(puVar2 + 6));
  *(undefined4 *)(puVar2 + 0x12) = *(undefined4 *)(puVar6 + 0x12);
  *(undefined4 *)(puVar2 + 0x14) = *(undefined4 *)(puVar6 + 0x14);
  *(undefined4 *)(puVar2 + 0x16) = *(undefined4 *)(puVar6 + 0x16);
  *puVar2 = *puVar6;
  puVar2[1] = puVar6[1];
  if ((*(byte *)(iVar3 + 0x160) >> 3 & 1) == 0) {
    uStack_1c = (uint)*(ushort *)(iVar3 + 0x146);
    local_20 = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    uStack_24 = (int)(short)puVar6[2] ^ 0x80000000;
    local_28 = 0x43300000;
    iVar1 = (int)((double)*(float *)(iVar3 + 0x138) * dVar7 +
                 (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7e10));
    local_30 = (longlong)iVar1;
    puVar2[2] = (ushort)iVar1;
  }
  *(byte *)(iVar3 + 0x160) = *(byte *)(iVar5 + 0x160) & 0x80 | *(byte *)(iVar3 + 0x160) & 0x7f;
  if (0 < *(short *)(iVar3 + 0x144)) {
    *(byte *)(iVar3 + 0x160) =
         (byte)((*(byte *)(iVar5 + 0x160) >> 3 & 1) << 3) | *(byte *)(iVar3 + 0x160) & 0xf7;
  }
  if (*(char *)(iVar5 + 0x159) == '\x04') {
    puVar2[3] = puVar2[3] | 0x4000;
    FUN_80035ff8((int)puVar2);
    *(undefined *)(iVar3 + 0x159) = 4;
    *(undefined *)(iVar3 + 0x159) = 4;
  }
  FUN_8028688c();
  return;
}

