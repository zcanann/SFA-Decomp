// Function: FUN_8014c11c
// Entry: 8014c11c
// Size: 956 bytes

void FUN_8014c11c(undefined4 param_1,undefined4 param_2,int param_3,short **param_4)

{
  short sVar1;
  short *psVar2;
  short *psVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  ulonglong uVar10;
  float local_48;
  int local_44;
  float local_40;
  float local_3c;
  float local_38;
  longlong local_30;
  
  uVar10 = FUN_802860c8();
  psVar2 = (short *)(uVar10 >> 0x20);
  local_48 = (float)extraout_f1;
  iVar8 = *(int *)(psVar2 + 0x5c);
  local_44 = 0;
  iVar7 = 0;
  if ((uVar10 & 1) == 0) {
    local_48 = (float)extraout_f1 * (float)extraout_f1;
    iVar5 = FUN_80036f50(3,&local_44);
    if (local_44 != 0) {
      for (iVar6 = 0; iVar6 < local_44; iVar6 = iVar6 + 1) {
        dVar9 = (double)FUN_800216d0(psVar2 + 0xc,*(int *)(iVar5 + iVar6 * 4) + 0x18);
        if ((dVar9 < (double)local_48) &&
           (psVar3 = *(short **)(iVar5 + iVar6 * 4), psVar3 != psVar2)) {
          *param_4 = psVar3;
          dVar9 = (double)FUN_802931a0();
          local_30 = (longlong)(int)dVar9;
          *(short *)(param_4 + 1) = (short)(int)dVar9;
          if ((uVar10 & 2) != 0) {
            if ((*(uint *)(iVar8 + 0x2e4) & 0x8000) == 0) {
              psVar3 = *param_4;
              local_40 = *(float *)(psVar2 + 0xc) - *(float *)(psVar3 + 0xc);
              local_3c = *(float *)(psVar2 + 0xe) - *(float *)(psVar3 + 0xe);
              local_38 = *(float *)(psVar2 + 0x10) - *(float *)(psVar3 + 0x10);
            }
            else {
              local_40 = *(float *)(psVar2 + 0xc) - *(float *)(*param_4 + 0xc);
              local_3c = FLOAT_803e2574;
              local_38 = *(float *)(psVar2 + 0x10) - *(float *)(*param_4 + 0x10);
            }
            uVar4 = FUN_800217c0(-(double)local_40,-(double)local_38);
            if (*(short **)(psVar2 + 0x18) == (short *)0x0) {
              sVar1 = *psVar2;
            }
            else {
              sVar1 = *psVar2 + **(short **)(psVar2 + 0x18);
            }
            uVar4 = (uVar4 & 0xffff) - ((int)sVar1 & 0xffffU);
            if (0x8000 < (int)uVar4) {
              uVar4 = uVar4 - 0xffff;
            }
            if ((int)uVar4 < -0x8000) {
              uVar4 = uVar4 + 0xffff;
            }
            sVar1 = (short)((uVar4 & 0xffff) >> 0xd);
            *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & ~(&DAT_8031dbf0)[sVar1];
            if ((uVar10 & 4) != 0) {
              *(uint *)(*(int *)(*param_4 + 0x5c) + 0x2dc) =
                   *(uint *)(*(int *)(*param_4 + 0x5c) + 0x2dc) & ~(&DAT_8031dc10)[sVar1];
            }
          }
          param_4 = param_4 + 2;
          iVar7 = iVar7 + 1;
          if (param_3 <= iVar7) {
            iVar6 = local_44;
          }
        }
      }
    }
  }
  else {
    psVar3 = (short *)FUN_80036e58(3,psVar2,&local_48);
    *param_4 = psVar3;
    if (psVar3 != (short *)0x0) {
      local_30 = (longlong)(int)local_48;
      *(short *)(param_4 + 1) = (short)(int)local_48;
      iVar7 = 1;
      if ((uVar10 & 2) != 0) {
        if ((*(uint *)(iVar8 + 0x2e4) & 0x8000) == 0) {
          psVar3 = *param_4;
          local_40 = *(float *)(psVar2 + 0xc) - *(float *)(psVar3 + 0xc);
          local_3c = *(float *)(psVar2 + 0xe) - *(float *)(psVar3 + 0xe);
          local_38 = *(float *)(psVar2 + 0x10) - *(float *)(psVar3 + 0x10);
        }
        else {
          local_40 = *(float *)(psVar2 + 0xc) - *(float *)(*param_4 + 0xc);
          local_3c = FLOAT_803e2574;
          local_38 = *(float *)(psVar2 + 0x10) - *(float *)(*param_4 + 0x10);
        }
        uVar4 = FUN_800217c0(-(double)local_40,-(double)local_38);
        if (*(short **)(psVar2 + 0x18) == (short *)0x0) {
          sVar1 = *psVar2;
        }
        else {
          sVar1 = *psVar2 + **(short **)(psVar2 + 0x18);
        }
        uVar4 = (uVar4 & 0xffff) - ((int)sVar1 & 0xffffU);
        if (0x8000 < (int)uVar4) {
          uVar4 = uVar4 - 0xffff;
        }
        if ((int)uVar4 < -0x8000) {
          uVar4 = uVar4 + 0xffff;
        }
        sVar1 = (short)((uVar4 & 0xffff) >> 0xd);
        *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & ~(&DAT_8031dbf0)[sVar1];
        if ((uVar10 & 4) != 0) {
          *(uint *)(*(int *)(*param_4 + 0x5c) + 0x2dc) =
               *(uint *)(*(int *)(*param_4 + 0x5c) + 0x2dc) & ~(&DAT_8031dc10)[sVar1];
        }
      }
    }
  }
  FUN_80286114(iVar7);
  return;
}

