// Function: FUN_801702d4
// Entry: 801702d4
// Size: 172 bytes

/* WARNING: Removing unreachable block (ram,0x80170364) */

int FUN_801702d4(double param_1,int param_2)

{
  char cVar2;
  int iVar1;
  undefined4 uVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  cVar2 = FUN_8002e04c();
  if (cVar2 == '\0') {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_8002bdf4(0x24,0x836);
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_2 + 0x18);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_2 + 0x1c);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_2 + 0x20);
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 1;
    *(undefined *)(iVar1 + 7) = 0xff;
    iVar1 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (iVar1 != 0) {
      *(float *)(iVar1 + 8) = (float)param_1;
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return iVar1;
}

