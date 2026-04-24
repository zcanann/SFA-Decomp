// Function: FUN_8003ea84
// Entry: 8003ea84
// Size: 1128 bytes

void FUN_8003ea84(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5,
                 int param_6)

{
  char cVar1;
  bool bVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  int iVar8;
  char *pcVar9;
  float *pfVar10;
  int iVar11;
  int iVar12;
  uint *unaff_r22;
  double dVar13;
  double dVar14;
  undefined8 uVar15;
  char local_88;
  char local_87;
  char local_86;
  char local_85;
  float afStack_84 [13];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  uVar15 = FUN_80286820();
  iVar5 = (int)((ulonglong)uVar15 >> 0x20);
  pcVar9 = (char *)uVar15;
  bVar2 = true;
  if ((*param_3 != 0) || (param_3[1] != 0)) {
    bVar4 = 0;
    for (iVar12 = 0; iVar12 < (int)(uint)(byte)pcVar9[0x41]; iVar12 = iVar12 + 1) {
      iVar8 = FUN_8004c3cc((int)pcVar9,iVar12);
      if ((*(byte *)(iVar8 + 4) & 0x80) != 0) {
        bVar4 = bVar4 + 1;
      }
    }
    if (1 < bVar4) {
      bVar2 = false;
    }
  }
  iVar12 = 0;
  do {
    if ((int)(uint)(byte)pcVar9[0x41] <= iVar12) {
LAB_8003eed4:
      FUN_8028686c();
      return;
    }
    puVar6 = (uint *)FUN_8004c3cc((int)pcVar9,iVar12);
    if ((*(byte *)(puVar6 + 1) & 0x80) == param_4) {
      if (((*(uint *)(pcVar9 + 0x3c) & 0x100000) != 0) && (iVar12 == 1)) {
        FUN_80050fa4(*param_3 != 0);
        goto LAB_8003eed4;
      }
      cVar1 = (char)((*(byte *)(iVar5 + 0x37) + 1) * (uint)(byte)pcVar9[0xc] >> 8);
      if (*puVar6 == 0) {
        local_88 = pcVar9[4];
        local_87 = pcVar9[5];
        local_86 = pcVar9[6];
        if ((*param_3 == 0) && (((*pcVar9 != -1 || (pcVar9[1] != -1)) || (pcVar9[2] != -1)))) {
          if (param_5 == 0) {
            if ((pcVar9[0x40] & 0x10U) == 0) {
              local_85 = cVar1;
              FUN_80052668(&local_88);
            }
            else {
              local_85 = cVar1;
              FUN_8005254c();
              if (local_85 != -1) {
                FUN_800528e0(&local_88);
              }
            }
          }
          else {
            DAT_803dd8d4._3_1_ = cVar1;
            local_85 = cVar1;
            FUN_800528e0((char *)&DAT_803dd8d4);
          }
        }
        else {
          local_85 = cVar1;
          FUN_800528e0(&local_88);
        }
      }
      else {
        uVar7 = FUN_8005383c(*puVar6);
        if (*(char *)((int)puVar6 + 5) == '\0') {
          pfVar10 = (float *)0x0;
        }
        else {
          iVar8 = *(int *)(*(int *)(iVar5 + 0x50) + 0xc);
          iVar11 = 0;
          for (uVar3 = (uint)*(byte *)(*(int *)(iVar5 + 0x50) + 0x59); uVar3 != 0; uVar3 = uVar3 - 1
              ) {
            if (*(char *)((int)puVar6 + 5) == *(char *)(iVar8 + 1)) {
              uVar7 = FUN_80054dac(uVar7,*(int *)(*(int *)(iVar5 + 0x70) + iVar11 * 0x10));
              break;
            }
            iVar8 = iVar8 + 2;
            iVar11 = iVar11 + 1;
          }
          iVar8 = *(int *)(*(int *)(iVar5 + 0x50) + 0xc);
          iVar11 = 0;
          for (uVar3 = (uint)*(byte *)(*(int *)(iVar5 + 0x50) + 0x59); uVar3 != 0; uVar3 = uVar3 - 1
              ) {
            if (*(char *)((int)puVar6 + 5) == *(char *)(iVar8 + 1)) {
              iVar8 = *(int *)(iVar5 + 0x70) + iVar11 * 0x10;
              uStack_4c = (int)*(short *)(iVar8 + 8) ^ 0x80000000;
              local_50 = 0x43300000;
              dVar13 = (double)(FLOAT_803df6c8 *
                               (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df6c0));
              uStack_44 = (int)*(short *)(iVar8 + 10) ^ 0x80000000;
              local_48 = 0x43300000;
              dVar14 = (double)(FLOAT_803df6c8 *
                               (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df6c0));
              goto LAB_8003eca4;
            }
            iVar8 = iVar8 + 2;
            iVar11 = iVar11 + 1;
          }
          dVar13 = (double)FLOAT_803df684;
          dVar14 = dVar13;
LAB_8003eca4:
          FUN_80247a48(dVar13,dVar14,(double)FLOAT_803df684,afStack_84);
          pfVar10 = afStack_84;
        }
        if (iVar12 == 0) {
          if ((((*param_3 == 0) && (param_3[1] == 0)) && (param_6 == 0)) || (!bVar2)) {
            uVar3 = 0;
            local_85 = cVar1;
          }
          else {
            uVar3 = 8;
            local_85 = cVar1;
          }
        }
        else {
          uVar3 = *(byte *)(unaff_r22 + 1) & 0x7f;
          local_85 = -1;
        }
        local_88 = -1;
        local_87 = -1;
        local_86 = -1;
        if ((*param_3 == 0) && (((*pcVar9 != -1 || (pcVar9[1] != -1)) || (pcVar9[2] != -1)))) {
          if (param_5 == 0) {
            if ((pcVar9[0x40] & 0x10U) == 0) {
              FUN_80051ed8(uVar7,pfVar10,uVar3,&local_88);
            }
            else {
              FUN_800519e4(uVar7,pfVar10,uVar3);
              if (local_85 != -1) {
                FUN_800528e0(&local_88);
              }
            }
          }
          else {
            DAT_803dd8d4._3_1_ = local_85;
            if ((pcVar9[0x40] & 0x10U) == 0) {
              FUN_80052134(uVar7,pfVar10,uVar3,(char *)&DAT_803dd8d4,(uint)*(byte *)(param_3 + 2),1)
              ;
            }
            else {
              FUN_80051c7c(uVar7,pfVar10,uVar3,(char *)&DAT_803dd8d4);
            }
          }
        }
        else {
          FUN_80052134(uVar7,pfVar10,uVar3,&local_88,(uint)*(byte *)(param_3 + 2),1);
        }
      }
    }
    iVar12 = iVar12 + 1;
    unaff_r22 = puVar6;
  } while( true );
}

