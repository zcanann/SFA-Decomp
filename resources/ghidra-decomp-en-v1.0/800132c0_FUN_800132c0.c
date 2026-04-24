// Function: FUN_800132c0
// Entry: 800132c0
// Size: 372 bytes

int FUN_800132c0(undefined4 param_1)

{
  int iVar1;
  undefined4 local_18;
  int local_14;
  int local_10 [2];
  
  iVar1 = FUN_80043588(0x1a,param_1,&local_18);
  if (iVar1 == 0) {
    FUN_8007d6dc(s__voxLoadVoxMapActual__Warning_vo_802c6230);
    iVar1 = 0;
  }
  else {
    FUN_80048d78(local_18,local_10,&local_14);
    if (local_10[0] < 1) {
      iVar1 = 0;
    }
    else if (local_14 < 0x7801) {
      if (local_14 < 1) {
        FUN_8007d6dc(s__voxLoadVoxMapActual__Warning_un_802c629c);
        iVar1 = 0;
      }
      else {
        iVar1 = FUN_80023cc8(local_14,0x10,0);
        if (iVar1 == 0) {
          FUN_8007d6dc(s__WARNING__Voxmap_has_no_mem_avai_802c62d4);
          iVar1 = 0;
        }
        else {
          FUN_800464c8(0x1b,iVar1,local_18,local_10[0],0,0,0);
          if (iVar1 == 0) {
            FUN_8007d6dc(s__WARNING__Voxmap_has_no_mem_avai_802c62d4);
            iVar1 = 0;
          }
          else {
            *(int *)(iVar1 + 0x1c) = *(int *)(iVar1 + 0x1c) + iVar1;
            *(int *)(iVar1 + 0x24) = *(int *)(iVar1 + 0x24) + iVar1;
            *(int *)(iVar1 + 0x14) = *(int *)(iVar1 + 0x14) + iVar1;
            *(int *)(iVar1 + 0x20) = *(int *)(iVar1 + 0x20) + iVar1;
            *(int *)(iVar1 + 0x28) = *(int *)(iVar1 + 0x28) + iVar1;
            *(int *)(iVar1 + 0x18) = *(int *)(iVar1 + 0x18) + iVar1;
          }
        }
      }
    }
    else {
      FUN_801378a8(s_VOXMAP__Size_overflow_on_load__I_802c6264);
      iVar1 = 0;
    }
  }
  return iVar1;
}

