// Function: FUN_8019ed98
// Entry: 8019ed98
// Size: 920 bytes

void FUN_8019ed98(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  ushort *puVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  int iVar9;
  char cVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  double dVar15;
  float local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  puVar5 = (ushort *)FUN_80286830();
  iVar13 = *(int *)(puVar5 + 0x26);
  iVar12 = *(int *)(puVar5 + 0x5c);
  if (puVar5[0x5a] != 4) {
    *(undefined *)(param_3 + 0x56) = 0;
    iVar6 = FUN_8002bac4();
    fVar1 = *(float *)(iVar6 + 0xc) - *(float *)(iVar13 + 8);
    fVar2 = *(float *)(iVar6 + 0x14) - *(float *)(iVar13 + 0x10);
    iVar4 = (int)*(short *)(iVar13 + 0x1a) / 2;
    uStack_3c = iVar4 * iVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    bVar14 = fVar1 * fVar1 + fVar2 * fVar2 <
             (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4eb8);
    *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) & 0xf7;
    iVar9 = *(int *)(puVar5 + 0x5c);
    iVar4 = FUN_8002bac4();
    iVar11 = *(int *)(puVar5 + 0x26);
    bVar3 = false;
    dVar15 = (double)FUN_800217c8((float *)(iVar4 + 0x18),(float *)(puVar5 + 0xc));
    uStack_34 = (int)*(short *)(iVar11 + 0x1a) ^ 0x80000000;
    local_38 = 0x43300000;
    if (((dVar15 < (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4eb8)) &&
        (*(int *)(iVar9 + 0x230) == 3)) && ((puVar5[0x58] & 0x1000) == 0)) {
      bVar3 = true;
    }
    if (bVar3) {
      *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) & 0xef;
    }
    else {
      *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) | 0x10;
    }
    if ((!bVar14) && (*(int *)(iVar12 + 0x230) == 2)) {
      uStack_34 = (int)*(short *)(iVar13 + 0x18) ^ 0x80000000;
      local_38 = 0x43300000;
      local_48[0] = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4eb8);
      iVar4 = FUN_80036f50(3,puVar5,local_48);
      if (iVar4 != 0) {
        bVar14 = true;
      }
    }
    for (cVar10 = '\0'; (int)cVar10 < (int)(uint)*(byte *)(param_3 + 0x8b); cVar10 = cVar10 + '\x01'
        ) {
      if (*(char *)(param_3 + cVar10 + 0x81) == '\x01') {
        FUN_8000bb38(0,0x109);
      }
    }
    *(undefined4 *)(iVar12 + 0xc4) = 0;
    switch(*(undefined4 *)(iVar12 + 0xc4)) {
    case 0:
    case 8:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
      uVar7 = FUN_800386e0(puVar5,iVar6,(float *)0x0);
      FUN_8003aebc(puVar5,iVar6,iVar12 + 0x3c,0x28,0,3);
      *puVar5 = *puVar5 + ((short)uVar7 >> 3) + (ushort)((short)uVar7 < 0 && (uVar7 & 7) != 0);
      if (bVar14) {
        *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
      }
      else {
        *(undefined *)(param_3 + 0x90) = 8;
      }
      break;
    case 5:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
      iVar13 = FUN_8002ba84();
      uVar7 = FUN_800386e0(puVar5,iVar13,(float *)0x0);
      uVar8 = FUN_8002ba84();
      FUN_8003aebc(puVar5,uVar8,iVar12 + 0x3c,0x28,0,3);
      *puVar5 = *puVar5 + ((short)uVar7 >> 3) + (ushort)((short)uVar7 < 0 && (uVar7 & 7) != 0);
      break;
    case 10:
    case 0xb:
      if (*(int *)(iVar12 + 0x114) != 0) {
        *(float *)(iVar12 + 0xac) = *(float *)(iVar12 + 0xac) * FLOAT_803e4ee0;
        *(undefined4 *)(*(int *)(iVar12 + 0x114) + 8) = *(undefined4 *)(iVar12 + 0xac);
      }
      *(undefined4 *)(iVar12 + 0xc4) = 0xb;
      dVar15 = (double)FUN_800217c8((float *)(puVar5 + 0xc),(float *)(iVar6 + 0x18));
      uStack_34 = (int)*(short *)(iVar13 + 0x1a) ^ 0x80000000;
      local_38 = 0x43300000;
      if ((dVar15 < (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4eb8)) &&
         ((*(byte *)((int)puVar5 + 0xaf) & 1) != 0)) {
        *(undefined4 *)(iVar12 + 0xc4) = 7;
        goto LAB_8019f118;
      }
    }
  }
LAB_8019f118:
  FUN_8028687c();
  return;
}

