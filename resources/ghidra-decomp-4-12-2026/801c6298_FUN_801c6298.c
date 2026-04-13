// Function: FUN_801c6298
// Entry: 801c6298
// Size: 348 bytes

void FUN_801c6298(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_8028683c();
  piVar5 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
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
        FUN_80296c78(iVar3,8,1);
        FUN_800201ac(0x143,1);
        FUN_800201ac(0xba8,1);
        break;
      case '\r':
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x48,100,0,0x50);
        break;
      case '\x0e':
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_8001dc30((double)FLOAT_803e5c60,*piVar5,'\0');
        }
        break;
      case '\x0f':
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_8001dc30((double)FLOAT_803e5c60,*piVar5,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}

