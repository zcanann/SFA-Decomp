// Function: FUN_8009b0e0
// Entry: 8009b0e0
// Size: 372 bytes

void FUN_8009b0e0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,uint param_5)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  char *pcVar4;
  int iVar5;
  uint *puVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d4();
  iVar2 = (int)uVar7;
  puVar6 = &DAT_8039bc18 + iVar2;
  if ((1 << param_3 & *puVar6) != 0) {
    iVar5 = (int)((ulonglong)uVar7 >> 0x20) + param_3 * 0xa0;
    *(undefined4 *)(iVar5 + 0x7c) = 0;
    if (param_4 == 0) {
      if ((&DAT_8039b4e0)[(uint)(*(byte *)(iVar5 + 0x8a) >> 1) * 4] != 0) {
        DAT_803dd258 = 1;
        FUN_80054308((&DAT_8039b4e0)[(uint)(*(byte *)(iVar5 + 0x8a) >> 1) * 4]);
        DAT_803dd258 = 0;
      }
      uVar1 = (uint)(*(byte *)(iVar5 + 0x8a) >> 1);
      psVar3 = &DAT_8039b4e4 + uVar1 * 8;
      if (*psVar3 == 0) {
        FUN_801378a8(s_expgfx_c__mismatch_in_add_remove_8030fbf0);
      }
      else {
        *psVar3 = *psVar3 + -1;
        if (*psVar3 == 0) {
          (&DAT_8039b4e0)[uVar1 * 4] = 0;
          (&DAT_8039b4d8)[uVar1 * 4] = 0;
        }
      }
    }
    *(undefined2 *)(iVar5 + 0x26) = 0xffff;
    if ((param_5 & 0xff) != 0) {
      FUN_802419e8(iVar5,0xa0);
    }
    *puVar6 = *puVar6 & ~(1 << param_3);
    pcVar4 = &DAT_8039bbc8 + iVar2;
    *pcVar4 = *pcVar4 + -1;
    if (*pcVar4 == '\0') {
      (&DAT_8030f8c8)[iVar2] = 0xffff;
    }
  }
  FUN_80286120();
  return;
}

