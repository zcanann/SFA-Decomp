// Function: FUN_801d90f0
// Entry: 801d90f0
// Size: 544 bytes

void FUN_801d90f0(int param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  
  uVar1 = FUN_80020078(0x1ab);
  if (uVar1 == 0) {
    if (*(short *)((int)param_2 + 0x12) == 0xcc) {
      *(undefined2 *)((int)param_2 + 0x12) = 0xffff;
    }
  }
  else if (*(short *)((int)param_2 + 0x12) != 0xcc) {
    *(undefined2 *)((int)param_2 + 0x12) = 0xcc;
    FUN_800201ac(0xc0,1);
    *param_2 = *param_2 & 0xfffffffd;
  }
  if (*(byte *)(param_2 + 1) < 2) {
    *(byte *)(param_2 + 1) = *(byte *)(param_2 + 1) + 1;
  }
  else {
    uVar1 = FUN_80020078(0xb);
    if (uVar1 == 0) {
      FUN_80014b94(0);
      FUN_80014b84(0);
      FUN_80014b68(0,0x100);
      FUN_80014b68(0,0x200);
      FUN_80014b68(0,0x1000);
      iVar2 = FUN_8002bac4();
      if ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        FUN_800201ac(0xb,1);
      }
    }
    if ((*param_2 & 0x80) == 0) {
      FUN_800201ac(0x2ba,0);
      *param_2 = *param_2 | 0x80;
    }
  }
  uVar1 = FUN_80020078(0x2da);
  if ((((uVar1 == 0) && (uVar1 = FUN_80020078(0x34a), uVar1 != 0)) &&
      (uVar1 = FUN_80020078(0x36f), uVar1 != 0)) &&
     (((uVar1 = FUN_80020078(0x166), uVar1 != 0 && (uVar1 = FUN_80020078(0x167), uVar1 != 0)) &&
      (iVar2 = FUN_8002bac4(), (*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)))) {
    FUN_800201ac(0x2da,1);
  }
  cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_1 + 0xac),6);
  if (cVar3 == '\0') {
    iVar2 = FUN_8002bac4();
    uVar1 = FUN_80296c50(iVar2,0);
    if (uVar1 != 0) {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0xac),6,1);
    }
  }
  return;
}

