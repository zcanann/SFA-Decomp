// Function: FUN_800e67ac
// Entry: 800e67ac
// Size: 368 bytes

void FUN_800e67ac(void)

{
  float fVar1;
  undefined2 *puVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  undefined2 local_78;
  undefined2 local_76;
  undefined2 local_74;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined auStack96 [96];
  
  uVar10 = FUN_802860d8();
  puVar2 = (undefined2 *)((ulonglong)uVar10 >> 0x20);
  puVar5 = (uint *)uVar10;
  uVar3 = *puVar5;
  if (((uVar3 & 0x4000000) != 0) && ((uVar3 & 8) != 0)) {
    local_78 = *puVar2;
    if ((uVar3 & 0x20) == 0) {
      local_76 = puVar2[1];
      local_74 = puVar2[2];
    }
    else {
      local_76 = 0;
      local_74 = 0;
    }
    local_70 = FLOAT_803e068c;
    local_6c = *(undefined4 *)(puVar2 + 6);
    local_68 = *(undefined4 *)(puVar2 + 8);
    local_64 = *(undefined4 *)(puVar2 + 10);
    FUN_80021ee8(auStack96,&local_78);
    iVar9 = 0;
    iVar7 = 0;
    puVar4 = puVar5;
    for (iVar8 = 0; fVar1 = FLOAT_803e068c, iVar8 < (int)(*(byte *)(puVar5 + 0x97) & 0xf);
        iVar8 = iVar8 + 1) {
      pfVar6 = (float *)(puVar5[0x37] + iVar7);
      FUN_800226cc((double)*pfVar6,(double)pfVar6[1],(double)pfVar6[2],auStack96,puVar4 + 0x39,
                   puVar5 + iVar9 + 0x3a,puVar5 + iVar9 + 0x3b);
      puVar4 = puVar4 + 3;
      iVar7 = iVar7 + 0xc;
      iVar9 = iVar9 + 3;
    }
    puVar4 = puVar5;
    for (iVar7 = 0; iVar7 < (int)(*(byte *)(puVar5 + 0x97) & 0xf); iVar7 = iVar7 + 1) {
      puVar4[0x45] = puVar4[0x39];
      puVar4[0x46] = (uint)(fVar1 + (float)puVar4[0x3a]);
      puVar4[0x47] = puVar4[0x3b];
      puVar4 = puVar4 + 3;
    }
    FUN_80063368(puVar2);
  }
  FUN_80286124();
  return;
}

