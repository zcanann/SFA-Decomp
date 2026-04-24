// Function: FUN_80241f6c
// Entry: 80241f6c
// Size: 244 bytes

void FUN_80241f6c(void)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_8024035c();
  if ((uVar1 & 0x8000) == 0) {
    FUN_80241b28();
    FUN_80246e04(s_L1_i_caches_initialized_8032c74c);
  }
  uVar1 = FUN_8024035c();
  if ((uVar1 & 0x4000) == 0) {
    FUN_802419a4();
    FUN_80246e04(s_L1_d_caches_initialized_8032c768);
  }
  uVar1 = FUN_8024036c();
  if ((uVar1 & 0x80000000) == 0) {
    uVar2 = FUN_8024034c();
    sync(0);
    FUN_80240354(0x30);
    sync(0);
    sync(0);
    uVar1 = FUN_8024036c();
    FUN_80240374(uVar1 & 0x7fffffff);
    sync(0);
    FUN_80241d74();
    FUN_80240354(uVar2);
    uVar1 = FUN_8024036c();
    FUN_80240374(uVar1 & 0xffdfffff | 0x80000000);
    FUN_80246e04(s_L2_cache_initialized_8032c784);
  }
  FUN_802429f4(1,&LAB_80241e0c);
  FUN_80246e04(s_Locked_cache_machine_check_handl_8032c79c);
  return;
}

