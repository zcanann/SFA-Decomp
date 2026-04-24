// Function: FUN_800191c4
// Entry: 800191c4
// Size: 640 bytes

undefined2 * FUN_800191c4(undefined4 param_1,int param_2)

{
  int iVar1;
  short *psVar2;
  undefined2 *puVar3;
  
  if (*(int *)(DAT_803dc9ec + 0x1c) == 2) {
    psVar2 = (short *)FUN_80019570();
    if (*psVar2 == -1) {
      DAT_803dc97c = DAT_803dc97c + 1;
      if (7 < DAT_803dc97c) {
        DAT_803dc97c = 0;
      }
      DAT_803dc974 = (undefined2 *)(&DAT_803399c0 + DAT_803dc97c * 0xc);
      DAT_803dc978 = *(undefined4 *)(&DAT_803399c8)[DAT_803dc97c * 3];
      *DAT_803dc974 = 0xffff;
      DAT_803dc970 = DAT_803dc97c * 4 + -0x7fcc6660;
      FUN_8028f688(DAT_803dc978,s___d_s_not_in__s__802c9e3c,param_1,
                   (&PTR_s_Animtest_802c729c)[DAT_803dc9dc]);
      puVar3 = DAT_803dc974;
    }
    else if (param_2 < (int)(uint)(ushort)psVar2[1]) {
      puVar3 = *(undefined2 **)(*(int *)(psVar2 + 4) + param_2 * 4);
    }
    else {
      DAT_803dc97c = DAT_803dc97c + 1;
      if (7 < DAT_803dc97c) {
        DAT_803dc97c = 0;
      }
      DAT_803dc974 = (undefined2 *)(&DAT_803399c0 + DAT_803dc97c * 0xc);
      DAT_803dc978 = *(undefined4 *)(&DAT_803399c8)[DAT_803dc97c * 3];
      *DAT_803dc974 = 0xffff;
      DAT_803dc970 = DAT_803dc97c * 4 + -0x7fcc6660;
      FUN_8028f688(DAT_803dc978,s___d__doesn_t_have_phrase__d__802c9e50,param_1,param_2);
      puVar3 = DAT_803dc974;
    }
  }
  else {
    DAT_803dc97c = DAT_803dc97c + 1;
    if (7 < DAT_803dc97c) {
      DAT_803dc97c = 0;
    }
    DAT_803dc974 = (undefined2 *)(&DAT_803399c0 + DAT_803dc97c * 0xc);
    DAT_803dc978 = *(undefined4 *)(&DAT_803399c8)[DAT_803dc97c * 3];
    *DAT_803dc974 = 0xffff;
    DAT_803dc970 = DAT_803dc97c * 4 + -0x7fcc6660;
    iVar1 = *(int *)(DAT_803dc9ec + 0x1c);
    puVar3 = DAT_803dc974;
    if (iVar1 != 2) {
      if (iVar1 < 2) {
        if (iVar1 == 0) {
          FUN_8028f688(DAT_803dc978,s__uninitialised__802c9e04);
          puVar3 = DAT_803dc974;
        }
        else if (-1 < iVar1) {
          FUN_8028f688(DAT_803dc978,s__loading__802c9e14);
          puVar3 = DAT_803dc974;
        }
      }
      else if (iVar1 == 4) {
        FUN_8028f688(DAT_803dc978,s__no_file___802c9e30);
        puVar3 = DAT_803dc974;
      }
      else if (iVar1 < 4) {
        FUN_8028f688(DAT_803dc978,s__file_empty___802c9e20);
        puVar3 = DAT_803dc974;
      }
    }
  }
  return puVar3;
}

