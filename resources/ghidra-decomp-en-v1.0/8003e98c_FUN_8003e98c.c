// Function: FUN_8003e98c
// Entry: 8003e98c
// Size: 1128 bytes

void FUN_8003e98c(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5,
                 int param_6)

{
  char cVar1;
  byte bVar3;
  uint uVar2;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  int iVar7;
  char *pcVar8;
  undefined *puVar9;
  int iVar10;
  int iVar11;
  int *unaff_r22;
  int iVar12;
  double dVar13;
  double dVar14;
  undefined8 uVar15;
  char local_88;
  char local_87;
  char local_86;
  char local_85;
  undefined auStack132 [52];
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  
  uVar15 = FUN_802860bc();
  iVar4 = (int)((ulonglong)uVar15 >> 0x20);
  pcVar8 = (char *)uVar15;
  iVar12 = 1;
  if ((*param_3 != 0) || (param_3[1] != 0)) {
    bVar3 = 0;
    for (iVar11 = 0; iVar11 < (int)(uint)(byte)pcVar8[0x41]; iVar11 = iVar11 + 1) {
      iVar7 = FUN_8004c250(pcVar8,iVar11);
      if ((*(byte *)(iVar7 + 4) & 0x80) != 0) {
        bVar3 = bVar3 + 1;
      }
    }
    if (1 < bVar3) {
      iVar12 = 0;
    }
  }
  iVar11 = 0;
  do {
    if ((int)(uint)(byte)pcVar8[0x41] <= iVar11) {
LAB_8003eddc:
      FUN_80286108(iVar12);
      return;
    }
    piVar5 = (int *)FUN_8004c250(pcVar8,iVar11);
    if ((*(byte *)(piVar5 + 1) & 0x80) == param_4) {
      if (((*(uint *)(pcVar8 + 0x3c) & 0x100000) != 0) && (iVar11 == 1)) {
        FUN_80050e28(*param_3 != 0);
        iVar12 = 1;
        goto LAB_8003eddc;
      }
      cVar1 = (char)((*(byte *)(iVar4 + 0x37) + 1) * (uint)(byte)pcVar8[0xc] >> 8);
      if (*piVar5 == 0) {
        local_88 = pcVar8[4];
        local_87 = pcVar8[5];
        local_86 = pcVar8[6];
        if ((*param_3 == 0) && (((*pcVar8 != -1 || (pcVar8[1] != -1)) || (pcVar8[2] != -1)))) {
          if (param_5 == 0) {
            if ((pcVar8[0x40] & 0x10U) == 0) {
              local_85 = cVar1;
              FUN_800524ec(&local_88);
            }
            else {
              local_85 = cVar1;
              FUN_800523d0();
              if (local_85 != -1) {
                FUN_80052764(&local_88);
              }
            }
          }
          else {
            DAT_803dcc54._3_1_ = cVar1;
            local_85 = cVar1;
            FUN_80052764(&DAT_803dcc54);
          }
        }
        else {
          local_85 = cVar1;
          FUN_80052764(&local_88);
        }
      }
      else {
        uVar6 = FUN_800536c0();
        if (*(char *)((int)piVar5 + 5) == '\0') {
          puVar9 = (undefined *)0x0;
        }
        else {
          iVar7 = *(int *)(*(int *)(iVar4 + 0x50) + 0xc);
          iVar10 = 0;
          for (uVar2 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x59); uVar2 != 0; uVar2 = uVar2 - 1
              ) {
            if (*(char *)((int)piVar5 + 5) == *(char *)(iVar7 + 1)) {
              uVar6 = FUN_80054c30(uVar6,*(undefined4 *)(*(int *)(iVar4 + 0x70) + iVar10 * 0x10));
              break;
            }
            iVar7 = iVar7 + 2;
            iVar10 = iVar10 + 1;
          }
          iVar7 = *(int *)(*(int *)(iVar4 + 0x50) + 0xc);
          iVar10 = 0;
          for (uVar2 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x59); uVar2 != 0; uVar2 = uVar2 - 1
              ) {
            if (*(char *)((int)piVar5 + 5) == *(char *)(iVar7 + 1)) {
              iVar7 = *(int *)(iVar4 + 0x70) + iVar10 * 0x10;
              uStack76 = (int)*(short *)(iVar7 + 8) ^ 0x80000000;
              local_50 = 0x43300000;
              dVar13 = (double)(FLOAT_803dea48 *
                               (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dea40));
              uStack68 = (int)*(short *)(iVar7 + 10) ^ 0x80000000;
              local_48 = 0x43300000;
              dVar14 = (double)(FLOAT_803dea48 *
                               (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dea40));
              goto LAB_8003ebac;
            }
            iVar7 = iVar7 + 2;
            iVar10 = iVar10 + 1;
          }
          dVar13 = (double)FLOAT_803dea04;
          dVar14 = dVar13;
LAB_8003ebac:
          FUN_802472e4(dVar13,dVar14,(double)FLOAT_803dea04,auStack132);
          puVar9 = auStack132;
        }
        if (iVar11 == 0) {
          if ((((*param_3 == 0) && (param_3[1] == 0)) && (param_6 == 0)) || (iVar12 == 0)) {
            bVar3 = 0;
            local_85 = cVar1;
          }
          else {
            bVar3 = 8;
            local_85 = cVar1;
          }
        }
        else {
          bVar3 = *(byte *)(unaff_r22 + 1) & 0x7f;
          local_85 = -1;
        }
        local_88 = -1;
        local_87 = -1;
        local_86 = -1;
        if ((*param_3 == 0) && (((*pcVar8 != -1 || (pcVar8[1] != -1)) || (pcVar8[2] != -1)))) {
          if (param_5 == 0) {
            if ((pcVar8[0x40] & 0x10U) == 0) {
              FUN_80051d5c(uVar6,puVar9,bVar3,&local_88);
            }
            else {
              FUN_80051868(uVar6,puVar9,bVar3);
              if (local_85 != -1) {
                FUN_80052764(&local_88);
              }
            }
          }
          else {
            DAT_803dcc54._3_1_ = local_85;
            if ((pcVar8[0x40] & 0x10U) == 0) {
              FUN_80051fb8(uVar6,puVar9,bVar3,&DAT_803dcc54,*(undefined *)(param_3 + 2),1);
            }
            else {
              FUN_80051b00(uVar6,puVar9,bVar3,&DAT_803dcc54);
            }
          }
        }
        else {
          FUN_80051fb8(uVar6,puVar9,bVar3,&local_88,*(undefined *)(param_3 + 2),1);
        }
      }
    }
    iVar11 = iVar11 + 1;
    unaff_r22 = piVar5;
  } while( true );
}

