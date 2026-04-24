// Function: FUN_800e64f4
// Entry: 800e64f4
// Size: 696 bytes

void FUN_800e64f4(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined2 *puVar5;
  int iVar6;
  uint *puVar7;
  uint *puVar8;
  float *pfVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  undefined2 local_78;
  undefined2 local_76;
  undefined2 local_74;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined auStack96 [96];
  
  uVar13 = FUN_802860d8();
  puVar5 = (undefined2 *)((ulonglong)uVar13 >> 0x20);
  puVar8 = (uint *)uVar13;
  if ((*puVar8 & 0x4000000) != 0) {
    if (*(int *)(puVar5 + 0x18) == 0) {
      *(undefined4 *)(puVar5 + 0xc) = *(undefined4 *)(puVar5 + 6);
      *(undefined4 *)(puVar5 + 0xe) = *(undefined4 *)(puVar5 + 8);
      *(undefined4 *)(puVar5 + 0x10) = *(undefined4 *)(puVar5 + 10);
    }
    else if ((*(int *)(*(int *)(puVar5 + 0x18) + 0x58) == 0) || (iVar6 = FUN_80035f7c(), iVar6 == 0)
            ) {
      FUN_8000e0a0((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                   (double)*(float *)(puVar5 + 10),puVar5 + 0xc,puVar5 + 0xe,puVar5 + 0x10,
                   *(undefined4 *)(puVar5 + 0x18));
    }
    else {
      FUN_800226cc((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                   (double)*(float *)(puVar5 + 10),
                   *(int *)(*(int *)(puVar5 + 0x18) + 0x58) +
                   (*(byte *)(*(int *)(*(int *)(puVar5 + 0x18) + 0x58) + 0x10c) + 2) * 0x40,
                   puVar5 + 0xc,puVar5 + 0xe,puVar5 + 0x10);
    }
    if ((*puVar8 & 0x2000) != 0) {
      local_78 = *puVar5;
      if ((*puVar8 & 0x20) == 0) {
        local_76 = puVar5[1];
        local_74 = puVar5[2];
      }
      else {
        local_76 = 0;
        local_74 = 0;
      }
      local_70 = FLOAT_803e068c;
      local_6c = *(undefined4 *)(puVar5 + 0xc);
      local_68 = *(undefined4 *)(puVar5 + 0xe);
      local_64 = *(undefined4 *)(puVar5 + 0x10);
      FUN_80021ee8(auStack96,&local_78);
      iVar12 = 0;
      iVar6 = 0;
      puVar7 = puVar8;
      for (iVar11 = 0; fVar2 = FLOAT_803e06b8, iVar11 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4;
          iVar11 = iVar11 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar6);
        FUN_800226cc((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],auStack96,puVar7 + 2,
                     puVar8 + iVar12 + 3,puVar8 + iVar12 + 4);
        *(undefined *)((int)puVar8 + iVar11 + 0xb8) = 0xff;
        puVar7 = puVar7 + 3;
        iVar6 = iVar6 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar7 = puVar8;
      puVar10 = puVar8;
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar6 = iVar6 + 1) {
        puVar7[0xe] = puVar7[2];
        puVar7[0xf] = (uint)(fVar2 + (float)puVar7[3] + (float)puVar10[0x2a]);
        puVar7[0x10] = puVar7[4];
        puVar7 = puVar7 + 3;
        puVar10 = puVar10 + 1;
      }
    }
    if (puVar5[0x22] == 1) {
      uVar1 = *(uint *)(puVar5 + 0xc);
      puVar8[8] = uVar1;
      puVar8[0x14] = uVar1;
      fVar2 = FLOAT_803e06bc + *(float *)(puVar5 + 0xe);
      puVar8[9] = (uint)fVar2;
      puVar8[0x15] = (uint)fVar2;
      uVar1 = *(uint *)(puVar5 + 0x10);
      puVar8[10] = uVar1;
      puVar8[0x16] = uVar1;
    }
    *(undefined *)(puVar8 + 0x98) = 0;
    *(undefined *)((int)puVar8 + 0x25f) = 0;
    fVar3 = FLOAT_803e06a4;
    puVar8[0x6f] = (uint)FLOAT_803e06a4;
    puVar8[0x6e] = (uint)fVar3;
    fVar4 = FLOAT_803e06a8;
    puVar8[0x6c] = (uint)FLOAT_803e06a8;
    fVar2 = FLOAT_803e0668;
    puVar8[0x6d] = (uint)FLOAT_803e0668;
    puVar8[0x6b] = (uint)fVar2;
    puVar8[0x36] = 0;
    puVar7 = puVar8;
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar6 = iVar6 + 1) {
      puVar7[0x80] = (uint)fVar3;
      puVar7[0x7c] = (uint)fVar3;
      puVar7[0x74] = (uint)fVar4;
      puVar7 = puVar7 + 1;
    }
  }
  FUN_80286124();
  return;
}

