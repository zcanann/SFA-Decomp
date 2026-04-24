// Function: FUN_8017c8b8
// Entry: 8017c8b8
// Size: 596 bytes

void FUN_8017c8b8(int param_1)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((*pbVar3 & 1) == 0) {
    if ((*pbVar3 & 2) == 0) {
      if (((*(short *)(iVar2 + 0x1a) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) &&
         ((*(short *)(iVar2 + 0x18) == -1 || (iVar1 = FUN_8001ffb4(), iVar1 == 0)))) {
        if ((*(byte *)(iVar2 + 0x1d) & 4) != 0) {
          FUN_800200e8((int)*(short *)(iVar2 + 0x1a),0);
          FUN_8007d6dc(s_newseqobj__d__need_bit_clear_bef_8032133c,*(undefined4 *)(iVar2 + 0x14));
        }
        if ((*(byte *)(iVar2 + 0x1d) & 0x20) != 0) {
          FUN_800200e8((int)*(short *)(iVar2 + 0x18),1);
          FUN_8007d6dc(s_newseqobj__d__used_bit_set_befor_8032136c,*(undefined4 *)(iVar2 + 0x14));
        }
        FUN_8007d6dc(s_newseqobj__d__about_to_start_the_80321398,*(undefined4 *)(iVar2 + 0x14));
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,0xffffffff);
      }
    }
    else {
      if ((*(byte *)(iVar2 + 0x1d) & 2) != 0) {
        FUN_800200e8((int)*(short *)(iVar2 + 0x1a),0);
        FUN_8007d6dc(s_newseqobj__d__need_bit_clear_aft_803212e0,*(undefined4 *)(iVar2 + 0x14));
      }
      if ((*(byte *)(iVar2 + 0x1d) & 0x10) != 0) {
        FUN_800200e8((int)*(short *)(iVar2 + 0x18),1);
        FUN_8007d6dc(s_newseqobj__d__used_bit_set_after_80321310,*(undefined4 *)(iVar2 + 0x14));
      }
      *pbVar3 = *pbVar3 & 0xfd;
    }
  }
  else {
    if ((*(byte *)(iVar2 + 0x1d) & 1) != 0) {
      FUN_800200e8((int)*(short *)(iVar2 + 0x1a),0);
      FUN_8007d6dc(s_newseqobj__d__need_bit_clear_bef_80321234,*(undefined4 *)(iVar2 + 0x14));
    }
    if ((*(byte *)(iVar2 + 0x1d) & 8) != 0) {
      FUN_800200e8((int)*(short *)(iVar2 + 0x18),1);
      FUN_8007d6dc(s_newseqobj__d__used_bit_set_befor_80321270,*(undefined4 *)(iVar2 + 0x14));
    }
    FUN_8007d6dc(s_newseqobj__d__about_to_prempt_th_803212a8,*(undefined4 *)(iVar2 + 0x14),
                 *(undefined2 *)(iVar2 + 0x22));
    (**(code **)(*DAT_803dca54 + 0x54))(param_1,(int)*(short *)(iVar2 + 0x20));
    (**(code **)(*DAT_803dca54 + 0x48))
              ((int)*(char *)(iVar2 + 0x1e),param_1,*(undefined2 *)(iVar2 + 0x22));
    *pbVar3 = *pbVar3 & 0xfe;
  }
  return;
}

