// Function: FUN_8014c594
// Entry: 8014c594
// Size: 956 bytes

void FUN_8014c594(undefined4 param_1,undefined4 param_2,int param_3,int *param_4)

{
  ushort uVar1;
  ushort *puVar2;
  uint uVar3;
  undefined4 *puVar4;
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
  
  uVar10 = FUN_8028682c();
  puVar2 = (ushort *)(uVar10 >> 0x20);
  local_48 = (float)extraout_f1;
  iVar8 = *(int *)(puVar2 + 0x5c);
  local_44 = 0;
  iVar7 = 0;
  if ((uVar10 & 1) == 0) {
    local_48 = (float)extraout_f1 * (float)extraout_f1;
    puVar4 = FUN_80037048(3,&local_44);
    if (local_44 != 0) {
      for (iVar6 = 0; iVar6 < local_44; iVar6 = iVar6 + 1) {
        dVar9 = FUN_80021794((float *)(puVar2 + 0xc),(float *)(puVar4[iVar6] + 0x18));
        if ((dVar9 < (double)local_48) && ((ushort *)puVar4[iVar6] != puVar2)) {
          *param_4 = (int)puVar4[iVar6];
          dVar9 = FUN_80293900(dVar9);
          local_30 = (longlong)(int)dVar9;
          *(short *)(param_4 + 1) = (short)(int)dVar9;
          if ((uVar10 & 2) != 0) {
            if ((*(uint *)(iVar8 + 0x2e4) & 0x8000) == 0) {
              iVar5 = *param_4;
              local_40 = *(float *)(puVar2 + 0xc) - *(float *)(iVar5 + 0x18);
              local_3c = *(float *)(puVar2 + 0xe) - *(float *)(iVar5 + 0x1c);
              local_38 = *(float *)(puVar2 + 0x10) - *(float *)(iVar5 + 0x20);
            }
            else {
              local_40 = *(float *)(puVar2 + 0xc) - *(float *)(*param_4 + 0x18);
              local_3c = FLOAT_803e31fc;
              local_38 = *(float *)(puVar2 + 0x10) - *(float *)(*param_4 + 0x20);
            }
            uVar3 = FUN_80021884();
            if (*(short **)(puVar2 + 0x18) == (short *)0x0) {
              uVar1 = *puVar2;
            }
            else {
              uVar1 = *puVar2 + **(short **)(puVar2 + 0x18);
            }
            uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
            if (0x8000 < (int)uVar3) {
              uVar3 = uVar3 - 0xffff;
            }
            if ((int)uVar3 < -0x8000) {
              uVar3 = uVar3 + 0xffff;
            }
            iVar5 = (short)((uVar3 & 0xffff) >> 0xd) * 4;
            *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & ~*(uint *)(&DAT_8031e840 + iVar5);
            if ((uVar10 & 4) != 0) {
              *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) =
                   *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) & ~*(uint *)(&DAT_8031e860 + iVar5);
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
    iVar7 = FUN_80036f50(3,puVar2,&local_48);
    *param_4 = iVar7;
    if (iVar7 != 0) {
      local_30 = (longlong)(int)local_48;
      *(short *)(param_4 + 1) = (short)(int)local_48;
      if ((uVar10 & 2) != 0) {
        if ((*(uint *)(iVar8 + 0x2e4) & 0x8000) == 0) {
          iVar7 = *param_4;
          local_40 = *(float *)(puVar2 + 0xc) - *(float *)(iVar7 + 0x18);
          local_3c = *(float *)(puVar2 + 0xe) - *(float *)(iVar7 + 0x1c);
          local_38 = *(float *)(puVar2 + 0x10) - *(float *)(iVar7 + 0x20);
        }
        else {
          local_40 = *(float *)(puVar2 + 0xc) - *(float *)(*param_4 + 0x18);
          local_3c = FLOAT_803e31fc;
          local_38 = *(float *)(puVar2 + 0x10) - *(float *)(*param_4 + 0x20);
        }
        uVar3 = FUN_80021884();
        if (*(short **)(puVar2 + 0x18) == (short *)0x0) {
          uVar1 = *puVar2;
        }
        else {
          uVar1 = *puVar2 + **(short **)(puVar2 + 0x18);
        }
        uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
        if (0x8000 < (int)uVar3) {
          uVar3 = uVar3 - 0xffff;
        }
        if ((int)uVar3 < -0x8000) {
          uVar3 = uVar3 + 0xffff;
        }
        iVar7 = (short)((uVar3 & 0xffff) >> 0xd) * 4;
        *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & ~*(uint *)(&DAT_8031e840 + iVar7);
        if ((uVar10 & 4) != 0) {
          *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) =
               *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) & ~*(uint *)(&DAT_8031e860 + iVar7);
        }
      }
    }
  }
  FUN_80286878();
  return;
}

