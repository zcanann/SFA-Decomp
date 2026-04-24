// Function: FUN_801c5ce4
// Entry: 801c5ce4
// Size: 348 bytes

void FUN_801c5ce4(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_802860d8();
  piVar5 = *(int **)(iVar2 + 0xb8);
  uVar3 = FUN_8002b9ec();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    cVar1 = *(char *)(param_3 + iVar4 + 0x81);
    if (cVar1 != '\0') {
      switch(cVar1) {
      case '\x03':
        *(undefined *)(piVar5 + 0xc) = 1;
        break;
      case '\a':
        FUN_80296518(uVar3,8,1);
        FUN_800200e8(0x143,1);
        FUN_800200e8(0xba8,1);
        break;
      case '\r':
        (**(code **)(*DAT_803dca54 + 0x50))(0x48,100,0,0x50);
        break;
      case '\x0e':
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_8001db6c((double)FLOAT_803e4fc8,*piVar5,0);
        }
        break;
      case '\x0f':
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_8001db6c((double)FLOAT_803e4fc8,*piVar5,0);
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286124(0);
  return;
}

