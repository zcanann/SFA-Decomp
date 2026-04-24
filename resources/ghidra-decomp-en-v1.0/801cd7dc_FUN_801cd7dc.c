// Function: FUN_801cd7dc
// Entry: 801cd7dc
// Size: 620 bytes

void FUN_801cd7dc(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar3 = FUN_802860dc();
  iVar6 = *(int *)(iVar3 + 0xb8);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 2) {
      iVar4 = 100;
      if (*(short *)(iVar3 + 0x46) == 0x5d) {
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar3,0xd3,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        sVar2 = *(short *)(iVar6 + 2);
        if (sVar2 == 0) {
          do {
            (**(code **)(*DAT_803dca88 + 8))(iVar3,0xcd,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        else if (sVar2 == 1) {
          do {
            (**(code **)(*DAT_803dca88 + 8))(iVar3,0xcf,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        iVar4 = 200;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar3,0xcc,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    else if (bVar1 < 4) {
      iVar4 = 5;
      if (*(short *)(iVar3 + 0x46) == 0x5d) {
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar3,0xd4,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        sVar2 = *(short *)(iVar6 + 2);
        if (sVar2 == 0) {
          do {
            (**(code **)(*DAT_803dca88 + 8))(iVar3,0xce,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        else if (sVar2 == 1) {
          do {
            (**(code **)(*DAT_803dca88 + 8))(iVar3,0xd0,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
  }
  FUN_80286128(0);
  return;
}

