// Function: FUN_8009b36c
// Entry: 8009b36c
// Size: 372 bytes

void FUN_8009b36c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  char *pcVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar8 = FUN_80286838();
  iVar2 = (int)uVar8;
  puVar7 = &DAT_8039c878 + iVar2;
  if ((1 << param_11 & *puVar7) != 0) {
    uVar6 = (int)((ulonglong)uVar8 >> 0x20) + param_11 * 0xa0;
    *(undefined4 *)(uVar6 + 0x7c) = 0;
    if (param_12 == 0) {
      uVar5 = param_13;
      uVar8 = extraout_f1;
      if ((&DAT_8039c140)[(uint)(*(byte *)(uVar6 + 0x8a) >> 1) * 4] != 0) {
        DAT_803dded8 = 1;
        uVar8 = FUN_80054484();
        DAT_803dded8 = 0;
      }
      uVar1 = (uint)(*(byte *)(uVar6 + 0x8a) >> 1);
      psVar3 = &DAT_8039c144 + uVar1 * 8;
      if (*psVar3 == 0) {
        FUN_80137c30(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_expgfx_c__mismatch_in_add_remove_803107b0,psVar3,uVar1 * 0x10,param_12,uVar5,
                     param_14,param_15,param_16);
      }
      else {
        *psVar3 = *psVar3 + -1;
        if (*psVar3 == 0) {
          (&DAT_8039c140)[uVar1 * 4] = 0;
          (&DAT_8039c138)[uVar1 * 4] = 0;
        }
      }
    }
    *(undefined2 *)(uVar6 + 0x26) = 0xffff;
    if ((param_13 & 0xff) != 0) {
      FUN_802420e0(uVar6,0xa0);
    }
    *puVar7 = *puVar7 & ~(1 << param_11);
    pcVar4 = &DAT_8039c828 + iVar2;
    *pcVar4 = *pcVar4 + -1;
    if (*pcVar4 == '\0') {
      (&DAT_80310488)[iVar2] = 0xffff;
    }
  }
  FUN_80286884();
  return;
}

