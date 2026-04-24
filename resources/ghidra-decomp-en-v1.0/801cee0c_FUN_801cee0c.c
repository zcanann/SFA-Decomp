// Function: FUN_801cee0c
// Entry: 801cee0c
// Size: 424 bytes

/* WARNING: Removing unreachable block (ram,0x801cee50) */

void FUN_801cee0c(undefined4 param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = FUN_801ce078();
  if (iVar2 == 0) {
    bVar1 = *(byte *)(param_2 + 0x408);
    if (bVar1 == 2) {
      *(undefined **)(param_2 + 0x48) = &DAT_803dbf78;
      iVar2 = FUN_80037fa4(param_1,0x576);
      if (iVar2 != 0) {
        FUN_800200e8(0x578,2);
        FUN_8001fee8(0x576);
        (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
        *(undefined *)(param_2 + 0x408) = 3;
        *(byte *)(param_2 + 0x43c) = *(byte *)(param_2 + 0x43c) | 0x10;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        *(undefined **)(param_2 + 0x48) = &DAT_803dbf70;
        iVar2 = FUN_8001ffb4(0xd3);
        if (iVar2 != 0) {
          *(undefined *)(param_2 + 0x408) = 1;
        }
      }
      else {
        *(undefined **)(param_2 + 0x48) = &DAT_803dbf74;
        iVar2 = FUN_8001ffb4(0x578);
        if (iVar2 == 1) {
          *(undefined *)(param_2 + 0x408) = 2;
        }
        else if ((iVar2 < 1) && (-1 < iVar2)) {
          iVar2 = FUN_80037fa4(param_1,0x576);
          if (iVar2 != 0) {
            FUN_800200e8(0x578,1);
            FUN_8001fee8(0x576);
            (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
            *(byte *)(param_2 + 0x43c) = *(byte *)(param_2 + 0x43c) | 0x10;
            *(undefined *)(param_2 + 0x408) = 2;
          }
        }
        else {
          *(undefined *)(param_2 + 0x408) = 3;
        }
      }
    }
    else if (bVar1 < 4) {
      *(undefined **)(param_2 + 0x48) = &DAT_803dbf7c;
    }
  }
  return;
}

