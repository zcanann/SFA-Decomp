// Function: FUN_80119e00
// Entry: 80119e00
// Size: 200 bytes

undefined4 FUN_80119e00(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_80246a0c(-0x7fc57058,FUN_80119cc4,0,0x803a8fa8,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_80246a0c(-0x7fc57058,FUN_80119b88,param_2,0x803a8fa8,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_802446f8((undefined4 *)&DAT_803a7f88,&DAT_803a7f5c,3);
  FUN_802446f8((undefined4 *)&DAT_803a7f68,&DAT_803a7f50,3);
  DAT_803de314 = 1;
  DAT_803de310 = 1;
  return 1;
}

