// Function: FUN_801d8b00
// Entry: 801d8b00
// Size: 544 bytes

void FUN_801d8b00(int param_1,uint *param_2)

{
  int iVar1;
  char cVar3;
  undefined4 uVar2;
  
  iVar1 = FUN_8001ffb4(0x1ab);
  if (iVar1 == 0) {
    if (*(short *)((int)param_2 + 0x12) == 0xcc) {
      *(undefined2 *)((int)param_2 + 0x12) = 0xffff;
    }
  }
  else if (*(short *)((int)param_2 + 0x12) != 0xcc) {
    *(undefined2 *)((int)param_2 + 0x12) = 0xcc;
    FUN_800200e8(0xc0,1);
    *param_2 = *param_2 & 0xfffffffd;
  }
  if (*(byte *)(param_2 + 1) < 2) {
    *(byte *)(param_2 + 1) = *(byte *)(param_2 + 1) + 1;
  }
  else {
    iVar1 = FUN_8001ffb4(0xb);
    if (iVar1 == 0) {
      FUN_80014b68(0);
      FUN_80014b58(0);
      FUN_80014b3c(0,0x100);
      FUN_80014b3c(0,0x200);
      FUN_80014b3c(0,0x1000);
      iVar1 = FUN_8002b9ec();
      if ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) {
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        FUN_800200e8(0xb,1);
      }
    }
    if ((*param_2 & 0x80) == 0) {
      FUN_800200e8(0x2ba,0);
      *param_2 = *param_2 | 0x80;
    }
  }
  iVar1 = FUN_8001ffb4(0x2da);
  if ((((iVar1 == 0) && (iVar1 = FUN_8001ffb4(0x34a), iVar1 != 0)) &&
      (iVar1 = FUN_8001ffb4(0x36f), iVar1 != 0)) &&
     (((iVar1 = FUN_8001ffb4(0x166), iVar1 != 0 && (iVar1 = FUN_8001ffb4(0x167), iVar1 != 0)) &&
      (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)))) {
    FUN_800200e8(0x2da,1);
  }
  cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),6);
  if (cVar3 == '\0') {
    uVar2 = FUN_8002b9ec();
    iVar1 = FUN_802964f0(uVar2,0);
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),6,1);
    }
  }
  return;
}

