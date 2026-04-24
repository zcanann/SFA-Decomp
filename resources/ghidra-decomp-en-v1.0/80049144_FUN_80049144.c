// Function: FUN_80049144
// Entry: 80049144
// Size: 188 bytes

int FUN_80049144(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack88 [52];
  undefined4 local_24;
  
  iVar1 = (&DAT_8035f3e8)[param_1];
  if (iVar1 == 0) {
    FUN_80248b9c((&PTR_s_AUDIO_tab_802cb2f4)[param_1],auStack88);
    (&DAT_8035f0a8)[param_1] = local_24;
    uVar2 = FUN_80023cc8((&DAT_8035f0a8)[param_1] + 0x20,0x7d7d7d7d,0);
    (&DAT_8035f3e8)[param_1] = uVar2;
    FUN_802419b8((&DAT_8035f3e8)[param_1],(&DAT_8035f0a8)[param_1]);
    FUN_80015850(auStack88,(&DAT_8035f3e8)[param_1],(&DAT_8035f0a8)[param_1],0);
    FUN_80248c64(auStack88);
    iVar1 = (&DAT_8035f3e8)[param_1];
  }
  return iVar1;
}

