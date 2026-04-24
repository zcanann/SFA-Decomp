// Function: FUN_8001f0c0
// Entry: 8001f0c0
// Size: 904 bytes

void FUN_8001f0c0(void)

{
  int iVar1;
  double dVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  float local_e8;
  undefined4 local_e4;
  float local_e0;
  float afStack_dc [17];
  undefined4 local_98;
  uint uStack_94;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  longlong local_80;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  undefined4 local_68;
  uint uStack_64;
  longlong local_60;
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  
  pfVar3 = (float *)FUN_8000f56c();
  puVar7 = &DAT_8033cb20;
  for (iVar5 = 0; iVar5 < (int)(uint)DAT_803dd6b0; iVar5 = iVar5 + 1) {
    puVar6 = (undefined4 *)*puVar7;
    if (puVar6[0x16] == 1) {
      puVar6[0x4e] = (float)puVar6[0x4e] + (float)puVar6[0x4f];
      if (FLOAT_803df3e0 <= (float)puVar6[0x4e]) {
        puVar6[0x4e] = FLOAT_803df3e0;
        puVar6[0x16] = 2;
      }
    }
    else if (puVar6[0x16] == 3) {
      puVar6[0x4e] = (float)puVar6[0x4e] + (float)puVar6[0x4f];
      if ((float)puVar6[0x4e] <= FLOAT_803df408) {
        puVar6[0x4e] = FLOAT_803df408;
        puVar6[0x16] = 0;
        *(undefined *)(puVar6 + 0x13) = 0;
      }
    }
    if (*(char *)(puVar6 + 0x13) != '\0') {
      if (puVar6[0x14] != 4) {
        if ((ushort *)*puVar6 != (ushort *)0x0) {
          FUN_8002b2c0((ushort *)*puVar6,(float *)(puVar6 + 1),(float *)(puVar6 + 4),'\x01');
        }
        if (puVar6[0x18] == 0) {
          local_e8 = (float)puVar6[4] - FLOAT_803dda58;
          local_e4 = puVar6[5];
          local_e0 = (float)puVar6[6] - FLOAT_803dda5c;
          FUN_80247bf8(pfVar3,&local_e8,(float *)(puVar6 + 7));
        }
        else {
          puVar6[7] = puVar6[4];
          puVar6[8] = puVar6[5];
          puVar6[9] = puVar6[6];
        }
      }
      if ((ushort *)*puVar6 != (ushort *)0x0) {
        FUN_8002b270((ushort *)*puVar6,(float *)(puVar6 + 10),(float *)(puVar6 + 0xd));
      }
      if (puVar6[0x18] == 0) {
        FUN_80247cd8(pfVar3,(float *)(puVar6 + 0xd),(float *)(puVar6 + 0x10));
      }
      else {
        puVar6[0x10] = puVar6[0xd];
        puVar6[0x11] = puVar6[0xe];
        puVar6[0x12] = puVar6[0xf];
      }
      dVar2 = DOUBLE_803df3f0;
      if (puVar6[0xb6] == 0) {
        uStack_94 = (uint)*(byte *)(puVar6 + 0x2b);
        local_98 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803df3f0) *
                     (float)puVar6[0x4e]);
        local_90 = (longlong)iVar1;
        *(char *)(puVar6 + 0x2a) = (char)iVar1;
        uStack_84 = (uint)*(byte *)((int)puVar6 + 0xad);
        local_88 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_84) - dVar2) * (float)puVar6[0x4e])
        ;
        local_80 = (longlong)iVar1;
        *(char *)((int)puVar6 + 0xa9) = (char)iVar1;
        uStack_74 = (uint)*(byte *)((int)puVar6 + 0xae);
        local_78 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_74) - dVar2) * (float)puVar6[0x4e])
        ;
        local_70 = (longlong)iVar1;
        *(char *)((int)puVar6 + 0xaa) = (char)iVar1;
        uStack_64 = (uint)*(byte *)((int)puVar6 + 0xaf);
        local_68 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_64) - dVar2) * (float)puVar6[0x4e])
        ;
        local_60 = (longlong)iVar1;
        *(char *)((int)puVar6 + 0xab) = (char)iVar1;
        uStack_54 = (uint)*(byte *)(puVar6 + 0x41);
        local_58 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - dVar2) * (float)puVar6[0x4e])
        ;
        local_50 = (longlong)iVar1;
        *(char *)(puVar6 + 0x40) = (char)iVar1;
        uStack_44 = (uint)*(byte *)((int)puVar6 + 0x105);
        local_48 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_44) - dVar2) * (float)puVar6[0x4e])
        ;
        local_40 = (longlong)iVar1;
        *(char *)((int)puVar6 + 0x101) = (char)iVar1;
        uStack_34 = (uint)*(byte *)((int)puVar6 + 0x106);
        local_38 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) * (float)puVar6[0x4e])
        ;
        local_30 = (longlong)iVar1;
        *(char *)((int)puVar6 + 0x102) = (char)iVar1;
        uStack_24 = (uint)*(byte *)((int)puVar6 + 0x107);
        local_28 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) * (float)puVar6[0x4e])
        ;
        local_20 = (longlong)iVar1;
        *(char *)((int)puVar6 + 0x103) = (char)iVar1;
      }
      else {
        FUN_8001d22c((int)puVar6);
      }
      if (puVar6[0x14] == 8) {
        FUN_8002b454((short *)*puVar6,puVar6 + 0x5c);
        pfVar4 = (float *)FUN_8000f578();
        FUN_80247618((float *)(puVar6 + 0x5c),pfVar4,afStack_dc);
        FUN_80247618((float *)(puVar6 + 0x6c),afStack_dc,(float *)(puVar6 + 0x8c));
      }
    }
    puVar7 = puVar7 + 1;
  }
  return;
}

