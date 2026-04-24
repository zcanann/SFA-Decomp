// Function: FUN_80232278
// Entry: 80232278
// Size: 308 bytes

void FUN_80232278(short *param_1,undefined4 param_2,int param_3,char param_4)

{
  char cVar2;
  int iVar1;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [4];
  
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    FUN_8003842c(param_1,param_2,&local_28,&local_24,local_20,0);
    iVar1 = FUN_8002bdf4(0x20,0x6ae);
    *(undefined4 *)(iVar1 + 8) = local_28;
    *(undefined4 *)(iVar1 + 0xc) = local_24;
    *(undefined4 *)(iVar1 + 0x10) = local_20[0];
    *(char *)(iVar1 + 0x1a) = (char)((uint)(*param_1 + param_3 + 0x8000) >> 8);
    *(char *)(iVar1 + 0x19) = (char)((uint)-(int)param_1[1] >> 8);
    *(undefined *)(iVar1 + 0x18) = 0;
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    iVar1 = FUN_8002b5a0(param_1);
    if (iVar1 != 0) {
      if (param_4 != '\0') {
        FUN_8022e418(iVar1,1);
      }
      FUN_8022e600(iVar1,0x4b);
      FUN_8022e54c((double)FLOAT_803e71a8,iVar1);
      FUN_8000b4d0(iVar1,0x2b5,4);
    }
  }
  return;
}

