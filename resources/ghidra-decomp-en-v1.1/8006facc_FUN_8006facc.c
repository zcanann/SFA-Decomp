// Function: FUN_8006facc
// Entry: 8006facc
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x8006fd5c) */
/* WARNING: Removing unreachable block (ram,0x8006fadc) */

void FUN_8006facc(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  uint uVar7;
  short *psVar8;
  int iVar9;
  float *pfVar10;
  double dVar11;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar12;
  float fStack_58;
  float afStack_54 [3];
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar12 = FUN_80286840();
  psVar8 = (short *)((ulonglong)uVar12 >> 0x20);
  pfVar10 = (float *)uVar12;
  if (psVar8[0x22] == 1) {
    DAT_803ddc70 = *(byte *)((int)psVar8 + 0xad);
  }
  else if (psVar8[0x23] == 0x416) {
    DAT_803ddc70 = 3;
  }
  iVar9 = FUN_800658e4((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                       (double)*(float *)(psVar8 + 10),psVar8,&fStack_58,afStack_54,0);
  if (iVar9 == 0) {
    if ((param_4 & 0xff) == 1) {
      iVar9 = (uint)DAT_803ddc78 * 0x10;
      *(float *)(&DAT_80392a40 + iVar9) = *pfVar10;
      *(float *)(&DAT_80392a44 + iVar9) = FLOAT_803dfabc + pfVar10[1];
      *(float *)(&DAT_80392a48 + iVar9) = pfVar10[2];
      *(short *)(&DAT_80392a4c + iVar9) = *psVar8;
      (&DAT_80392a4e)[iVar9] = 0xff;
      (&DAT_80392a4f)[iVar9] = param_3;
      uVar7 = DAT_803ddc78 + 1;
      DAT_803ddc78 = (byte)uVar7;
      if (0xff < (uVar7 & 0xff)) {
        DAT_803ddc78 = 0;
      }
    }
    FUN_80247ef8(afStack_54,afStack_54);
    local_3c = FLOAT_803dfab8;
    local_38 = FLOAT_803dfaa0;
    local_34 = FLOAT_803dfaa0;
    dVar11 = FUN_80247f90(afStack_54,&local_3c);
    if ((double)FLOAT_803dfad8 <= ABS(dVar11)) {
      local_3c = FLOAT_803dfaa0;
      local_34 = FLOAT_803dfab8;
    }
    FUN_80247fb0(afStack_54,&local_3c,&local_48);
    FUN_80247fb0(&local_48,afStack_54,&local_3c);
    FUN_80247ef8(&local_3c,&local_3c);
    FUN_80247ef8(&local_48,&local_48);
    dVar11 = (double)(float)(&DAT_80392a20)[DAT_803ddc70];
    FUN_80247edc(dVar11,&local_3c,&local_3c);
    FUN_80247edc(dVar11,&local_48,&local_48);
    fVar1 = *pfVar10;
    fVar2 = pfVar10[1];
    fVar3 = pfVar10[2];
    fVar4 = fVar1 - local_3c;
    uVar7 = (uint)DAT_803ddc79;
    iVar9 = uVar7 * 0x38;
    (&DAT_80393a40)[uVar7 * 0xe] = fVar4 - local_48;
    fVar5 = fVar2 - local_38;
    (&DAT_80393a44)[uVar7 * 0xe] = fVar5 - local_44;
    fVar6 = fVar3 - local_34;
    (&DAT_80393a48)[uVar7 * 0xe] = fVar6 - local_40;
    fVar1 = fVar1 + local_3c;
    (&DAT_80393a4c)[uVar7 * 0xe] = fVar1 - local_48;
    fVar2 = fVar2 + local_38;
    (&DAT_80393a50)[uVar7 * 0xe] = fVar2 - local_44;
    fVar3 = fVar3 + local_34;
    (&DAT_80393a54)[uVar7 * 0xe] = fVar3 - local_40;
    (&DAT_80393a58)[uVar7 * 0xe] = local_48 + fVar1;
    (&DAT_80393a5c)[uVar7 * 0xe] = local_44 + fVar2;
    (&DAT_80393a60)[uVar7 * 0xe] = local_40 + fVar3;
    (&DAT_80393a64)[uVar7 * 0xe] = local_48 + fVar4;
    (&DAT_80393a68)[uVar7 * 0xe] = local_44 + fVar5;
    (&DAT_80393a6c)[uVar7 * 0xe] = local_40 + fVar6;
    (&DAT_80393a70)[uVar7 * 0x1c] = -*psVar8;
    (&DAT_80393a72)[iVar9] = (char)param_4;
    (&DAT_80393a73)[iVar9] = 0xff;
    (&DAT_80393a74)[iVar9] = param_3;
    DAT_803ddc79 = (byte)(uVar7 + 1);
    if (0xff < (uVar7 + 1 & 0xff)) {
      DAT_803ddc79 = 0;
    }
  }
  FUN_8028688c();
  return;
}

