// Function: FUN_801b0848
// Entry: 801b0848
// Size: 220 bytes

void FUN_801b0848(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  if (param_6 != '\0') {
    piVar3 = *(int **)(iVar1 + 0xb8);
    iVar2 = piVar3[1];
    if (iVar2 != 0) {
      iVar2 = *(int *)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
      *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
      *(undefined *)(piVar3[1] + 0x37) = *(undefined *)(iVar1 + 0x37);
      FUN_8003b8f4((double)FLOAT_803e4820,piVar3[1]);
    }
    FUN_8003b8f4((double)FLOAT_803e4820,iVar1,(int)uVar4,param_3,param_4,param_5);
    iVar1 = *piVar3;
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_800604b4();
    }
  }
  FUN_80286124();
  return;
}

