// Function: FUN_8005b7d0
// Entry: 8005b7d0
// Size: 1132 bytes

void FUN_8005b7d0(void)

{
  float fVar1;
  short sVar2;
  char *pcVar3;
  undefined4 *puVar4;
  int iVar5;
  ushort *puVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  ushort *puVar12;
  float local_48;
  float fStack_44;
  float fStack_40;
  int local_3c [3];
  longlong local_30;
  
  pcVar3 = (char *)FUN_80286838();
  FUN_8006ca98();
  puVar4 = (undefined4 *)FUN_8002e1f4((undefined4 *)0x0,(undefined4 *)0x0);
  iVar5 = FUN_8002e288(local_3c);
  for (uVar11 = 0; (int)uVar11 < local_3c[0]; uVar11 = uVar11 + 1) {
    puVar12 = (ushort *)*puVar4;
    puVar12[0x58] = puVar12[0x58] & 0xf7ff;
    puVar6 = puVar12;
    for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)((int)puVar12 + 0xeb); iVar9 = iVar9 + 1) {
      iVar8 = *(int *)(puVar6 + 100);
      if (iVar8 != 0) {
        *(ushort *)(iVar8 + 0xb0) = *(ushort *)(iVar8 + 0xb0) & 0xf7ff;
      }
      puVar6 = puVar6 + 2;
    }
    if (iVar5 <= (int)uVar11) {
      uVar7 = FUN_8005a310((int)puVar12);
      *pcVar3 = (char)uVar7;
      if ((*pcVar3 == '\0') && ((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x200000) == 0)) {
        iVar9 = *(int *)(puVar12 + 0x2a);
        if ((iVar9 != 0) && ((*(byte *)(iVar9 + 0x62) & 0x30) != 0)) {
          *(undefined *)(iVar9 + 0xaf) = 2;
        }
      }
      else {
        if ((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x80000) == 0) {
          if (*(int *)(puVar12 + 0x18) == 0) {
            FUN_8000ef68((double)(*(float *)(puVar12 + 6) - FLOAT_803dda58),
                         (double)*(float *)(puVar12 + 8),
                         (double)(*(float *)(puVar12 + 10) - FLOAT_803dda5c),&fStack_40,&fStack_44,
                         &local_48,(float *)(puVar12 + 0x52));
          }
          else {
            FUN_8000ef68((double)*(float *)(puVar12 + 0xc),(double)*(float *)(puVar12 + 0xe),
                         (double)*(float *)(puVar12 + 0x10),&fStack_40,&fStack_44,&local_48,
                         (float *)(puVar12 + 0x52));
          }
          fVar1 = FLOAT_803df88c * (FLOAT_803df85c + local_48);
        }
        else {
          local_3c[2] = (uint)*(byte *)(*(int *)(puVar12 + 0x28) + 0x74) * 100 ^ 0x80000000;
          local_3c[1] = 0x43300000;
          *(float *)(puVar12 + 0x52) =
               (float)((double)CONCAT44(0x43300000,local_3c[2]) - DOUBLE_803df840);
          fVar1 = *(float *)(puVar12 + 0x52);
        }
        local_30 = (longlong)(int)fVar1;
        if ((((puVar12[3] & 0x4000) == 0) && (*(int *)(puVar12 + 0x32) != 0)) &&
           ((*(uint *)(*(int *)(puVar12 + 0x32) + 0x30) & 4) != 0)) {
          sVar2 = *(short *)(*(int *)(puVar12 + 0x28) + 0x48);
          if ((sVar2 == 2) || (sVar2 == 1)) {
            FUN_8006c500((int)puVar12);
          }
          else if (sVar2 == 4) {
            FUN_8006b6d4(puVar12);
          }
        }
        if (DAT_803ddb2e < 1000) {
          iVar9 = FUN_8002b660((int)puVar12);
          if (((*(char *)((int)puVar12 + 0x37) == -1) && ((puVar12[3] & 0x80) == 0)) &&
             (((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x40000) == 0 &&
              (*(int *)(iVar9 + 0x58) == 0)))) {
            uVar10 = 0x80000000;
            if (((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x800000) != 0) &&
               ((*(byte *)((int)puVar12 + 0xe5) & 2) == 0)) {
              uVar10 = ((int)(short)puVar12[0x23] & 0x3ffU) << 0x14 | 0xc0000000;
            }
            (&DAT_80387538)[DAT_803ddb2e] =
                 uVar11 & 0x3ff | (1000 - ((int)fVar1 & 0xffffU) & 0x3ff) << 10 | uVar10;
            DAT_803ddb2e = DAT_803ddb2e + 1;
            if ((((*(byte *)(*(int *)(puVar12 + 0x28) + 0x5f) & 0x20) != 0) &&
                ((puVar12[0x58] & 0x400) == 0)) && ((puVar12[3] & 0x4000) == 0)) {
              FUN_8005d2cc((int)puVar12,7,0x50);
              (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 1;
              DAT_803ddab0 = DAT_803ddab0 + 1;
            }
          }
          else {
            if (((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x800) == 0) &&
               ((*(byte *)(*(int *)(puVar12 + 0x28) + 0x5f) & 0x10) == 0)) {
              iVar9 = 7;
            }
            else {
              iVar9 = 0x1f;
            }
            FUN_8005d2cc((int)puVar12,iVar9,0);
            (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 0;
            DAT_803ddab0 = DAT_803ddab0 + 1;
            if (((*(byte *)(*(int *)(puVar12 + 0x28) + 0x5f) & 0x20) != 0) &&
               ((puVar12[3] & 0x4000) == 0)) {
              FUN_8005d2cc((int)puVar12,7,0x50);
              (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 1;
              DAT_803ddab0 = DAT_803ddab0 + 1;
            }
          }
        }
      }
    }
    puVar4 = puVar4 + 1;
    pcVar3 = pcVar3 + 1;
  }
  if (1 < DAT_803ddb2e) {
    FUN_8005b6e8(-0x7fc78ac8,(int)DAT_803ddb2e);
  }
  FUN_8006badc();
  FUN_80286884();
  return;
}

