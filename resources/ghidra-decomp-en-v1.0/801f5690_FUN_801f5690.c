// Function: FUN_801f5690
// Entry: 801f5690
// Size: 1116 bytes

undefined4 FUN_801f5690(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined auStack40 [24];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 0x12) & 1) != 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x7d8,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x7d8,auStack40,2,0xffffffff,0);
  }
  *(undefined *)(param_3 + 0x56) = 0;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  *(undefined **)(param_3 + 0xe8) = &DAT_801f568c;
  iVar4 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar4) {
      return 0;
    }
    switch(*(undefined *)(param_3 + iVar4 + 0x81)) {
    case 1:
      FUN_8004350c(0,0,1);
      break;
    case 2:
      iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
      if (iVar2 == 0x49781) {
        FUN_80042f78(0x42);
        uVar1 = FUN_800481b0(0x42);
        FUN_80043560(uVar1,0);
        uVar1 = FUN_800481b0(0xb);
        FUN_80043560(uVar1,1);
        (**(code **)(*DAT_803dcaac + 0x44))(0x42,3);
        (**(code **)(*DAT_803dcaac + 0x44))(7,5);
      }
      else if (iVar2 < 0x49781) {
        if (iVar2 == 0x47295) {
          FUN_80042f78(0x42);
          uVar1 = FUN_800481b0(0x42);
          FUN_80043560(uVar1,0);
          uVar1 = FUN_800481b0(0xb);
          FUN_80043560(uVar1,1);
          (**(code **)(*DAT_803dcaac + 0x44))(0x42,3);
          (**(code **)(*DAT_803dcaac + 0x44))(7,4);
        }
        else if ((iVar2 < 0x47295) && (iVar2 == 0x2183)) {
          uVar1 = FUN_800481b0(0x41);
          FUN_80043560(uVar1,0);
          uVar1 = FUN_800481b0(0xb);
          FUN_80043560(uVar1,1);
          (**(code **)(*DAT_803dcaac + 0x78))(1);
        }
      }
      else if (iVar2 == 0x4a1c0) {
        FUN_80042f78(0x42);
        uVar1 = FUN_800481b0(0x42);
        FUN_80043560(uVar1,0);
        uVar1 = FUN_800481b0(0xb);
        FUN_80043560(uVar1,1);
        (**(code **)(*DAT_803dcaac + 0x44))(0x42,3);
        (**(code **)(*DAT_803dcaac + 0x44))(7,7);
      }
      break;
    case 3:
      iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
      if (iVar2 == 0x49781) {
        FUN_800552e8(0x7e,0);
      }
      else if (iVar2 < 0x49781) {
        if (iVar2 == 0x47295) {
          FUN_800552e8(0x7e,0);
        }
      }
      else if (iVar2 == 0x4a1c0) {
        FUN_800552e8(0x7e,0);
      }
      break;
    case 4:
      iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
      if (iVar2 == 0x4a1c0) {
LAB_801f5854:
        *(undefined *)(iVar3 + 0x14) = 1;
      }
      else if (iVar2 < 0x4a1c0) {
        if ((iVar2 == 0x49781) || ((iVar2 < 0x49781 && (iVar2 == 0x47295)))) goto LAB_801f5854;
      }
      else if ((iVar2 == 0x4a5e6) || ((iVar2 < 0x4a5e6 && (iVar2 == 0x4a250)))) goto LAB_801f5854;
      break;
    case 5:
      *(byte *)(iVar3 + 0x12) = *(byte *)(iVar3 + 0x12) | 1;
      break;
    case 6:
      *(byte *)(iVar3 + 0x12) = *(byte *)(iVar3 + 0x12) & 0xfe;
      break;
    case 7:
      FUN_80088c94(7,0);
      FUN_8005cef0(1);
      FUN_80008cbc(param_1,param_1,0x84,0);
      FUN_80008cbc(param_1,param_1,0x8a,0);
      FUN_80008b74(0,0,0x217,0);
      FUN_80008b74(0,0,0x216,0);
      break;
    case 8:
      FUN_800550ac(1);
      break;
    case 9:
      FUN_800550ac(0);
    }
    iVar4 = iVar4 + 1;
  } while( true );
}

