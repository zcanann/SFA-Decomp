// Function: FUN_80054e14
// Entry: 80054e14
// Size: 188 bytes

void FUN_80054e14(undefined4 param_1,undefined4 param_2,int param_3,char param_4,uint param_5,
                 undefined param_6,undefined param_7,undefined param_8,undefined param_9)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286834();
  iVar1 = FUN_8025a850((uint)((ulonglong)uVar2 >> 0x20),(uint)uVar2,param_3,param_4,param_5);
  iVar1 = FUN_80023d8c(iVar1 + 0x60,6);
  if (iVar1 != 0) {
    FUN_800033a8(iVar1,0,100);
    *(char *)(iVar1 + 0x16) = (char)param_3;
    *(short *)(iVar1 + 10) = (short)((ulonglong)uVar2 >> 0x20);
    *(short *)(iVar1 + 0xc) = (short)uVar2;
    *(undefined2 *)(iVar1 + 0x10) = 1;
    *(undefined2 *)(iVar1 + 0xe) = 0;
    *(undefined *)(iVar1 + 0x17) = param_6;
    *(undefined *)(iVar1 + 0x18) = param_7;
    *(undefined *)(iVar1 + 0x19) = param_8;
    *(undefined *)(iVar1 + 0x1a) = param_9;
    *(undefined4 *)(iVar1 + 0x50) = 0;
    FUN_80053ed4(iVar1);
  }
  FUN_80286880();
  return;
}

