// Function: FUN_801d56c4
// Entry: 801d56c4
// Size: 540 bytes

void FUN_801d56c4(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  
  *(undefined **)(param_2 + 0x62c) = &DAT_803273d4;
  switch(*(undefined *)(param_2 + 0x626)) {
  case 1:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc000;
    break;
  case 2:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc000;
    break;
  case 3:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc000;
    break;
  case 4:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc000;
    break;
  case 5:
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc000;
    break;
  case 6:
    iVar1 = FUN_801d4cd0();
    if (iVar1 != 0) {
      *(undefined *)(param_2 + 0x624) = 0xe;
      return;
    }
    if (*(char *)(param_2 + 0x624) == '\x0e') {
      FUN_8000bb18(0,0x409);
      *(undefined *)(param_2 + 0x624) = 0;
      uVar2 = FUN_800221a0(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
    }
    *(undefined **)(param_2 + 0x62c) = &DAT_803dc000;
    break;
  case 7:
    if (*(char *)(param_2 + 0x624) == '\x0f') {
      FUN_8001ffb4(0x1a0);
      iVar1 = FUN_8001ffb4();
      if (iVar1 == 0) {
        return;
      }
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),3,0);
      *(undefined *)(param_2 + 0x624) = 0;
      uVar2 = FUN_800221a0(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
    }
    else {
      iVar1 = FUN_8001ffb4(0x1a0);
      if ((iVar1 == 0) && (iVar1 = FUN_80038024(param_1), iVar1 != 0)) {
        *(byte *)(param_2 + 0x625) = *(byte *)(param_2 + 0x625) | 4;
        *(undefined *)(param_2 + 0x624) = 0xf;
        (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),3,1);
        FUN_800200e8(0x199,1);
        return;
      }
    }
    break;
  case 8:
    *(undefined **)(param_2 + 0x62c) = &DAT_80327432;
  }
  FUN_801d5174(param_1,param_2);
  return;
}

