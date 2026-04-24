// Function: FUN_80048f48
// Entry: 80048f48
// Size: 324 bytes

void FUN_80048f48(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  ulonglong uVar5;
  undefined auStack88 [88];
  
  uVar5 = FUN_802860dc();
  iVar2 = (int)(uVar5 >> 0x20);
  uVar4 = (undefined4)uVar5;
  if (param_4 == 0) {
    param_4 = 0;
  }
  else if ((&DAT_8035f3e8)[iVar2] == 0) {
    FUN_80248b9c((&PTR_s_AUDIO_tab_802cb2f4)[iVar2],auStack88);
    if (((uVar5 & 0x1f) == 0) && ((param_4 & 0x1f) == 0)) {
      FUN_802419b8(uVar4,param_4);
      FUN_80015850(auStack88,uVar4,param_4,param_3);
    }
    else {
      uVar1 = param_4 + 0x1f & 0xffffffe0;
      uVar3 = FUN_80023cc8(uVar1,0x7d7d7d7d,0);
      FUN_802419b8(uVar3,uVar1);
      FUN_80015850(auStack88,uVar3,uVar1,param_3);
      FUN_80003494(uVar4,uVar3,param_4);
      FUN_80023800(uVar3);
    }
    FUN_80248c64(auStack88);
    FUN_80241a1c(uVar4,param_4);
  }
  else {
    FUN_80003494(uVar4,(&DAT_8035f3e8)[iVar2] + param_3,param_4);
    FUN_80241a1c(uVar4,param_4);
  }
  FUN_80286128(param_4);
  return;
}

