// Function: FUN_8023a168
// Entry: 8023a168
// Size: 256 bytes

void FUN_8023a168(short *param_1,int param_2)

{
  undefined extraout_var;
  char cVar3;
  short sVar2;
  int iVar1;
  
  cVar3 = FUN_8002e04c();
  if (cVar3 != '\0') {
    sVar2 = FUN_800221a0(0xffffe0c0,8000);
    FUN_800221a0(0xffffe0c0,8000);
    iVar1 = FUN_8002bdf4(0x20,0x80d);
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_2 + 0xc0);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_2 + 0xc4);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_2 + 200);
    *(char *)(iVar1 + 0x1a) = (char)((uint)((int)*param_1 + (int)(short)(sVar2 + -0x8000)) >> 8);
    *(undefined *)(iVar1 + 0x19) = extraout_var;
    *(undefined *)(iVar1 + 0x18) = 0;
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    iVar1 = FUN_8002b5a0(param_1);
    if (iVar1 != 0) {
      *(float *)(iVar1 + 8) = FLOAT_803e74b0;
      FUN_8022e600(iVar1,0x6e);
      FUN_8022e54c((double)FLOAT_803e74ac,iVar1);
    }
  }
  return;
}

