// Function: FUN_801f48c0
// Entry: 801f48c0
// Size: 652 bytes

/* WARNING: Removing unreachable block (ram,0x801f48fc) */

void FUN_801f48c0(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  char cVar5;
  int iVar3;
  undefined4 uVar4;
  int iVar6;
  float *pfVar7;
  undefined auStack40 [40];
  
  iVar2 = FUN_802860dc();
  pfVar7 = *(float **)(iVar2 + 0xb8);
  if (*(byte *)((int)pfVar7 + 5) == 0) {
    FUN_8002a774(iVar2,0);
  }
  else {
    uVar1 = (uint)*(byte *)((int)pfVar7 + 5) + (uint)DAT_803db410;
    if (0xff < uVar1) {
      uVar1 = 0xff;
    }
    *(char *)((int)pfVar7 + 5) = (char)uVar1;
    FUN_8002a774(iVar2);
  }
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
    switch(*(undefined *)(param_3 + iVar6 + 0x81)) {
    case 1:
      *(undefined *)(pfVar7 + 1) = 1;
      break;
    case 2:
      *(undefined *)(pfVar7 + 1) = 2;
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x556,0,2,0xffffffff,auStack40);
      FUN_8000bb18(iVar2,0x7b);
      FUN_8000bb18(iVar2,0x7c);
      *pfVar7 = FLOAT_803e5e98;
      break;
    case 3:
      *(undefined *)(pfVar7 + 1) = 3;
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x556,0,2,0xffffffff,0);
      FUN_8000bb18(iVar2,0x7b);
      FUN_8000bb18(iVar2,0x7c);
      *pfVar7 = FLOAT_803e5e9c;
      break;
    case 4:
      *(undefined *)(pfVar7 + 1) = 0;
      break;
    case 5:
      if ((*(int *)(iVar2 + 200) == 0) && (cVar5 = FUN_8002e04c(), cVar5 != '\0')) {
        iVar3 = FUN_8002bdf4(0x24,0x1b8);
        *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar2 + 0xc);
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar2 + 0x10);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar2 + 0x14);
        *(undefined *)(iVar3 + 4) = 0x20;
        *(undefined *)(iVar3 + 5) = 4;
        *(undefined *)(iVar3 + 7) = 0xff;
        uVar4 = FUN_8002df90(iVar3,5,0xffffffff,0xffffffff,0);
        FUN_80037d2c(iVar2,uVar4,0);
        *(float *)(*(int *)(iVar2 + 200) + 8) =
             *(float *)(*(int *)(iVar2 + 200) + 8) * FLOAT_803e5ea0;
      }
      break;
    case 6:
      if (*(int *)(iVar2 + 200) != 0) {
        FUN_80037cb0(iVar2);
      }
      break;
    case 7:
      *(byte *)(*(int *)(iVar2 + 0x50) + 0x5f) = *(byte *)(*(int *)(iVar2 + 0x50) + 0x5f) | 0x10;
      *(undefined *)((int)pfVar7 + 5) = 1;
      break;
    case 8:
      *(byte *)(*(int *)(iVar2 + 0x50) + 0x5f) = *(byte *)(*(int *)(iVar2 + 0x50) + 0x5f) & 0xef;
      FUN_8002a774(iVar2,0);
      *(undefined *)((int)pfVar7 + 5) = 0;
    }
    *(undefined *)(param_3 + iVar6 + 0x81) = 0;
  }
  FUN_80286128(0);
  return;
}

