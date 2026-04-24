// Function: FUN_80112d80
// Entry: 80112d80
// Size: 276 bytes

void FUN_80112d80(undefined4 param_1,undefined4 param_2,int param_3,short param_4,undefined *param_5
                 ,short param_6,short param_7,int param_8,char param_9)

{
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  uVar1 = (undefined4)((ulonglong)uVar3 >> 0x20);
  iVar2 = (int)uVar3;
  if (param_3 != 0) {
    *(undefined *)(param_3 + 0x24) = 0;
    *(undefined *)(param_3 + 0x25) = 0;
    *(undefined *)(param_3 + 0x26) = 4;
    *(undefined *)(param_3 + 0x27) = 0x14;
  }
  if (param_6 != -1) {
    *(short *)(iVar2 + 0x270) = param_6;
    *(undefined *)(iVar2 + 0x27b) = 1;
  }
  if (param_7 != -1) {
    (**(code **)(*DAT_803dca8c + 0x14))(uVar1,iVar2);
  }
  if (param_5 != (undefined *)0x0) {
    *param_5 = 2;
  }
  if (param_8 != 0) {
    FUN_80030334((double)FLOAT_803e1c2c,uVar1,param_8,0);
  }
  (**(code **)(*DAT_803dcaa8 + 0x20))(uVar1,iVar2 + 4);
  if (param_9 != -1) {
    *(char *)(iVar2 + 0x25f) = param_9;
  }
  if (param_4 != -1) {
    FUN_800200e8((int)param_4,1);
  }
  FUN_80286124();
  return;
}

