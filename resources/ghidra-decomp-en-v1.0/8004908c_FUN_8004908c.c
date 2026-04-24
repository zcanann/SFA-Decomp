// Function: FUN_8004908c
// Entry: 8004908c
// Size: 184 bytes

undefined4 FUN_8004908c(int param_1,undefined4 param_2)

{
  undefined auStack88 [52];
  undefined4 local_24;
  
  if ((&DAT_8035f3e8)[param_1] == 0) {
    FUN_80248b9c((&PTR_s_AUDIO_tab_802cb2f4)[param_1],auStack88);
    FUN_802419b8(param_2,local_24);
    FUN_80015850(auStack88,param_2,local_24,0);
    FUN_80248c64(auStack88);
  }
  else {
    FUN_80003494(param_2,(&DAT_8035f3e8)[param_1],(&DAT_8035f0a8)[param_1]);
    FUN_80241a1c(param_2,(&DAT_8035f0a8)[param_1]);
    local_24 = (&DAT_8035f0a8)[param_1];
  }
  return local_24;
}

