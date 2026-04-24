// Function: FUN_8022b764
// Entry: 8022b764
// Size: 316 bytes

void FUN_8022b764(short *param_1,int param_2,int param_3)

{
  char cVar3;
  int iVar1;
  undefined4 uVar2;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [5];
  
  cVar3 = FUN_8002e04c();
  if ((cVar3 != '\0') && (*(char *)(param_2 + 0x44c) != '\0')) {
    *(char *)(param_2 + 0x44c) = *(char *)(param_2 + 0x44c) + -1;
    if (param_3 == 0) {
      FUN_8003842c(param_1,5,&local_28,&local_24,local_20,0);
    }
    else {
      FUN_8003842c(param_1,6,&local_28,&local_24,local_20,0);
    }
    iVar1 = FUN_8002bdf4(0x20,0x605);
    *(undefined4 *)(iVar1 + 8) = local_28;
    *(undefined4 *)(iVar1 + 0xc) = local_24;
    *(undefined4 *)(iVar1 + 0x10) = local_20[0];
    *(char *)(iVar1 + 0x1a) = (char)((uint)(int)*param_1 >> 8);
    *(char *)(iVar1 + 0x19) = (char)((uint)(int)param_1[1] >> 8);
    *(char *)(iVar1 + 0x18) = (char)((uint)(int)param_1[2] >> 8);
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    uVar2 = FUN_8002b5a0(param_1);
    *(undefined4 *)(param_2 + 0x438) = uVar2;
    FUN_8022ed74(*(undefined4 *)(param_2 + 0x438),*(undefined2 *)(param_2 + 0x446));
    FUN_8022ece0((double)*(float *)(param_2 + 0x448),*(undefined4 *)(param_2 + 0x438));
    FUN_8000bb18(param_1,0x2a3);
  }
  return;
}

