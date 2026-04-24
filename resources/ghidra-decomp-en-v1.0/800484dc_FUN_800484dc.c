// Function: FUN_800484dc
// Entry: 800484dc
// Size: 720 bytes

void FUN_800484dc(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,int param_6,int param_7)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined auStack104 [104];
  
  uVar2 = FUN_802860cc();
  iVar5 = -1;
  if ((DAT_8035f468 != 0) || (DAT_8035f514 != 0)) {
    FUN_8024377c();
    uVar1 = DAT_803dcc80;
    FUN_802437a4();
    if (((uVar2 & 0x80000000) == 0) || ((uVar1 & 0x2000) != 0)) {
      if (((uVar2 & 0x40000000) == 0) || ((uVar1 & 0x1000) != 0)) {
        if ((DAT_8035f46c == 0) || (((uVar1 & 0x1000) != 0 || (DAT_8035f468 == 0)))) {
          if ((DAT_8035f518 != 0) && (((uVar1 & 0x2000) == 0 && (DAT_8035f514 != 0)))) {
            iVar5 = 0x4b;
          }
        }
        else {
          iVar5 = 0x20;
        }
      }
      else {
        iVar5 = 0x20;
      }
    }
    else {
      iVar5 = 0x4b;
    }
    iVar3 = (&DAT_8035f3e8)[iVar5];
    if (iVar3 == 0) {
      FUN_80248b9c((&PTR_s_AUDIO_tab_802cb2f4)[iVar5],auStack104);
      iVar5 = FUN_80023cc8(0x400,0x7f7f7fff,0);
      FUN_80015850(auStack104,iVar5,0x400,(uVar2 & 0xffffff) << 1);
      FUN_80248c64(auStack104);
      FUN_80241a1c(iVar5,0x400);
      if ((param_7 == 1) && (param_6 != 0)) {
        iVar3 = iVar5 + *(int *)(param_6 + param_5 * 4) + 4;
        uVar4 = *(undefined4 *)(iVar3 + 4);
        *param_4 = *(undefined4 *)(iVar3 + 8);
        *param_3 = uVar4;
      }
      else if ((param_7 == 2) && (param_6 != 0)) {
        FUN_80003494(param_6,iVar5,(param_5 + 1) * 4);
      }
      else {
        uVar4 = *(undefined4 *)(iVar5 + 0xc);
        *param_3 = *(undefined4 *)(iVar5 + 8);
        iVar3 = FUN_80291614(&DAT_803db5c4,iVar5,3);
        if (iVar3 == 0) {
          *param_4 = 0xffffffff;
        }
        else {
          *param_4 = uVar4;
        }
      }
      FUN_80023800(iVar5);
    }
    else if ((param_7 == 1) && (param_6 != 0)) {
      iVar3 = iVar3 + (uVar2 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar4 = *(undefined4 *)(iVar3 + 4);
      *param_4 = *(undefined4 *)(iVar3 + 8);
      *param_3 = uVar4;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,iVar3 + (uVar2 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar3 = iVar3 + (uVar2 & 0xffffff) * 2;
      uVar4 = *(undefined4 *)(iVar3 + 0xc);
      *param_3 = *(undefined4 *)(iVar3 + 8);
      iVar5 = FUN_80291614(&DAT_803db5c4,iVar3,3);
      if (iVar5 == 0) {
        *param_4 = 0xffffffff;
      }
      else {
        *param_4 = uVar4;
      }
    }
  }
  FUN_80286118();
  return;
}

