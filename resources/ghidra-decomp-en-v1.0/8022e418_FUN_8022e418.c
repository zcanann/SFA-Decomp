// Function: FUN_8022e418
// Entry: 8022e418
// Size: 308 bytes

void FUN_8022e418(int param_1,char param_2)

{
  undefined4 uVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((param_2 != '\0') && (*(int *)(iVar2 + 0x14) == 0)) {
    uVar1 = FUN_8001f4c8(param_1,1);
    *(undefined4 *)(iVar2 + 0x14) = uVar1;
    if (*(int *)(iVar2 + 0x14) != 0) {
      FUN_8001db2c(*(int *)(iVar2 + 0x14),2);
      dVar3 = (double)FLOAT_803e7008;
      FUN_8001dd88(dVar3,dVar3,dVar3,*(undefined4 *)(iVar2 + 0x14));
      FUN_8001db14(*(undefined4 *)(iVar2 + 0x14),1);
      if (*(short *)(param_1 + 0x46) == 0x6ae) {
        FUN_8001daf0(*(undefined4 *)(iVar2 + 0x14),0xff,0x14,0x50,0);
      }
      else if (*(char *)(param_1 + 0xad) == '\0') {
        FUN_8001daf0(*(undefined4 *)(iVar2 + 0x14),0x3c,0xff,0x5a,0);
      }
      else {
        FUN_8001daf0(*(undefined4 *)(iVar2 + 0x14),0x3c,0x5a,0xff,0);
      }
      if (*(short *)(param_1 + 0x46) == 0x655) {
        FUN_8001dc38((double)FLOAT_803e700c,(double)FLOAT_803e7010,*(undefined4 *)(iVar2 + 0x14));
      }
      else {
        FUN_8001dc38((double)FLOAT_803e7014,(double)FLOAT_803e7018,*(undefined4 *)(iVar2 + 0x14));
      }
      FUN_8001dd40(*(undefined4 *)(iVar2 + 0x14),1);
    }
  }
  return;
}

