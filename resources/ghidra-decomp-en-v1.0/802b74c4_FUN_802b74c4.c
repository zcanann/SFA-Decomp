// Function: FUN_802b74c4
// Entry: 802b74c4
// Size: 992 bytes

undefined4 FUN_802b74c4(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  if (*(int *)(param_2 + 0x2d0) != 0) {
    iVar3 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
    uVar1 = (uint)*(short *)(iVar3 + 0x20);
    if ((int)uVar1 < 0) {
      uVar1 = -uVar1;
    }
    if ((uVar1 & 0xffff) < 6000) {
      iVar4 = *(int *)(param_1 + 0x4c);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      iVar2 = *(int *)(iVar4 + 0x14);
      if (iVar2 == 0x46a55) {
        iVar2 = FUN_8001ffb4(0xc53);
        if (iVar2 != 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        }
      }
      else if (iVar2 < 0x46a55) {
        if ((iVar2 == 0x46a51) && (iVar2 = FUN_8001ffb4(0xc52), iVar2 != 0)) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        }
      }
      else if ((iVar2 == 0x49928) && (iVar2 = FUN_8001ffb4(0xc54), iVar2 != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        FUN_80014b3c(0,0x100);
        iVar2 = *(int *)(iVar4 + 0x14);
        if (iVar2 == 0x46a55) {
          iVar2 = FUN_8001ffb4(0xc3b);
          if (((iVar2 == 0) || (iVar2 = FUN_8001ffb4(0xc3c), iVar2 == 0)) ||
             (iVar2 = FUN_8001ffb4(0xc3d), iVar2 == 0)) {
            (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
          }
          else {
            iVar2 = FUN_8001ffb4(0xc53);
            if (iVar2 == 0) {
              FUN_800200e8(0xc53,1);
              (**(code **)(*DAT_803dca54 + 0x48))(5,param_1,0xffffffff);
              *(undefined *)(iVar3 + 0x2e) = 1;
              *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
            }
          }
        }
        else if (iVar2 < 0x46a55) {
          if (iVar2 == 0x46a51) {
            iVar2 = FUN_8001ffb4(0xc38);
            if (((iVar2 == 0) || (iVar2 = FUN_8001ffb4(0xc39), iVar2 == 0)) ||
               (iVar2 = FUN_8001ffb4(0xc3a), iVar2 == 0)) {
              (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
            }
            else {
              iVar2 = FUN_8001ffb4(0xc52);
              if (iVar2 == 0) {
                FUN_800200e8(0xc52,1);
                (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
                *(undefined *)(iVar3 + 0x2e) = 1;
                *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
              }
            }
          }
        }
        else if (iVar2 == 0x49928) {
          iVar2 = FUN_8001ffb4(0xc3e);
          if (((iVar2 == 0) || (iVar2 = FUN_8001ffb4(0xc3f), iVar2 == 0)) ||
             (iVar2 = FUN_8001ffb4(0xc40), iVar2 == 0)) {
            (**(code **)(*DAT_803dca54 + 0x48))(6,param_1,0xffffffff);
          }
          else {
            iVar2 = FUN_8001ffb4(0xc54);
            if (iVar2 == 0) {
              FUN_800200e8(0xc54,1);
              (**(code **)(*DAT_803dca54 + 0x48))(7,param_1,0xffffffff);
              *(undefined *)(iVar3 + 0x2e) = 1;
              *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
            }
          }
        }
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if ((*(char *)(param_2 + 0x27b) != '\0') || (*(char *)(param_2 + 0x346) != '\0')) {
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
    }
  }
  return 0;
}

