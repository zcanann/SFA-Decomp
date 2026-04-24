// Function: FUN_8019e81c
// Entry: 8019e81c
// Size: 920 bytes

void FUN_8019e81c(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  short *psVar5;
  undefined4 uVar6;
  int iVar7;
  ushort uVar8;
  int iVar9;
  char cVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  double dVar15;
  float local_48 [2];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  
  psVar5 = (short *)FUN_802860cc();
  iVar13 = *(int *)(psVar5 + 0x26);
  iVar12 = *(int *)(psVar5 + 0x5c);
  if (psVar5[0x5a] == 4) {
    uVar6 = 0;
  }
  else {
    *(undefined *)(param_3 + 0x56) = 0;
    iVar7 = FUN_8002b9ec();
    fVar1 = *(float *)(iVar7 + 0xc) - *(float *)(iVar13 + 8);
    fVar2 = *(float *)(iVar7 + 0x14) - *(float *)(iVar13 + 0x10);
    iVar4 = (int)*(short *)(iVar13 + 0x1a) / 2;
    uStack60 = iVar4 * iVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    bVar14 = fVar1 * fVar1 + fVar2 * fVar2 <
             (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4220);
    *(byte *)((int)psVar5 + 0xaf) = *(byte *)((int)psVar5 + 0xaf) & 0xf7;
    iVar9 = *(int *)(psVar5 + 0x5c);
    iVar4 = FUN_8002b9ec();
    iVar11 = *(int *)(psVar5 + 0x26);
    bVar3 = false;
    dVar15 = (double)FUN_80021704(iVar4 + 0x18,psVar5 + 0xc);
    uStack52 = (int)*(short *)(iVar11 + 0x1a) ^ 0x80000000;
    local_38 = 0x43300000;
    if (((dVar15 < (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e4220)) &&
        (*(int *)(iVar9 + 0x230) == 3)) && ((psVar5[0x58] & 0x1000U) == 0)) {
      bVar3 = true;
    }
    if (bVar3) {
      *(byte *)((int)psVar5 + 0xaf) = *(byte *)((int)psVar5 + 0xaf) & 0xef;
    }
    else {
      *(byte *)((int)psVar5 + 0xaf) = *(byte *)((int)psVar5 + 0xaf) | 0x10;
    }
    if ((!bVar14) && (*(int *)(iVar12 + 0x230) == 2)) {
      uStack52 = (int)*(short *)(iVar13 + 0x18) ^ 0x80000000;
      local_38 = 0x43300000;
      local_48[0] = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e4220);
      iVar4 = FUN_80036e58(3,psVar5,local_48);
      if (iVar4 != 0) {
        bVar14 = true;
      }
    }
    for (cVar10 = '\0'; (int)cVar10 < (int)(uint)*(byte *)(param_3 + 0x8b); cVar10 = cVar10 + '\x01'
        ) {
      if (*(char *)(param_3 + cVar10 + 0x81) == '\x01') {
        FUN_8000bb18(0,0x109);
      }
    }
    *(undefined4 *)(iVar12 + 0xc4) = 0;
    switch(*(undefined4 *)(iVar12 + 0xc4)) {
    case 0:
    case 8:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
      uVar8 = FUN_800385e8(psVar5,iVar7,0);
      FUN_8003adc4(psVar5,iVar7,iVar12 + 0x3c,0x28,0,3);
      *psVar5 = *psVar5 + ((short)uVar8 >> 3) + (ushort)((short)uVar8 < 0 && (uVar8 & 7) != 0);
      if (bVar14) {
        *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
      }
      else {
        *(undefined *)(param_3 + 0x90) = 8;
      }
      break;
    case 5:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
      uVar6 = FUN_8002b9ac();
      uVar8 = FUN_800385e8(psVar5,uVar6,0);
      uVar6 = FUN_8002b9ac();
      FUN_8003adc4(psVar5,uVar6,iVar12 + 0x3c,0x28,0,3);
      *psVar5 = *psVar5 + ((short)uVar8 >> 3) + (ushort)((short)uVar8 < 0 && (uVar8 & 7) != 0);
      break;
    case 10:
    case 0xb:
      if (*(int *)(iVar12 + 0x114) != 0) {
        *(float *)(iVar12 + 0xac) = *(float *)(iVar12 + 0xac) * FLOAT_803e4248;
        *(undefined4 *)(*(int *)(iVar12 + 0x114) + 8) = *(undefined4 *)(iVar12 + 0xac);
      }
      *(undefined4 *)(iVar12 + 0xc4) = 0xb;
      dVar15 = (double)FUN_80021704(psVar5 + 0xc,iVar7 + 0x18);
      uStack52 = (int)*(short *)(iVar13 + 0x1a) ^ 0x80000000;
      local_38 = 0x43300000;
      if ((dVar15 < (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e4220)) &&
         ((*(byte *)((int)psVar5 + 0xaf) & 1) != 0)) {
        *(undefined4 *)(iVar12 + 0xc4) = 7;
        uVar6 = 4;
        goto LAB_8019eb9c;
      }
    }
    uVar6 = 0;
  }
LAB_8019eb9c:
  FUN_80286118(uVar6);
  return;
}

