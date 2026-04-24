// Function: FUN_80026b3c
// Entry: 80026b3c
// Size: 244 bytes

void FUN_80026b3c(undefined4 param_1,undefined4 param_2,int *param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860d8();
  uVar1 = (undefined4)((ulonglong)uVar6 >> 0x20);
  uVar3 = (undefined4)uVar6;
  if (*(char *)((int)param_3 + 0x1a) != '\0') {
    iVar5 = 0;
    for (iVar4 = 0; iVar4 < param_3[1]; iVar4 = iVar4 + 1) {
      if (*(char *)((int)param_3 + 0x19) == '\0') {
        FUN_80026928(uVar1,uVar3,*param_3 + iVar5);
      }
      iVar2 = FUN_8002073c();
      if (iVar2 == 0) {
        FUN_80026790(uVar1,uVar3,param_3,*param_3 + iVar5);
        FUN_80026308(uVar1,uVar3,param_3,*param_3 + iVar5,param_4,iVar4);
      }
      else {
        FUN_80025f38(uVar1,uVar3,param_3,*param_3 + iVar5);
      }
      iVar5 = iVar5 + 0xc;
    }
    *(undefined *)(param_3 + 6) = 1;
    *(undefined *)((int)param_3 + 0x19) = 1;
  }
  FUN_80286124();
  return;
}

