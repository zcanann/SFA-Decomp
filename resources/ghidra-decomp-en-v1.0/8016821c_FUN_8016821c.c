// Function: FUN_8016821c
// Entry: 8016821c
// Size: 344 bytes

void FUN_8016821c(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  FLOAT_803dda94 =
       FLOAT_803e30a0 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
              DOUBLE_803e3070) / FLOAT_803e30a4;
  param_2[0x10] = (int)FLOAT_803e308c;
  FUN_8000bb18(param_1,0x276);
  iVar2 = 0x28;
  do {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x717,0,4,0xffffffff,&FLOAT_803dda94);
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  if ((*param_2 == 0) && (cVar1 = FUN_8002e04c(), cVar1 != '\0')) {
    iVar2 = FUN_8002bdf4(0x24,0x55e);
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
    *(float *)(iVar2 + 0xc) = FLOAT_803e30a8 + *(float *)(param_1 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)(iVar2 + 4) = *(undefined *)(iVar3 + 4);
    *(undefined *)(iVar2 + 5) = *(undefined *)(iVar3 + 5);
    *(undefined *)(iVar2 + 6) = *(undefined *)(iVar3 + 6);
    *(undefined *)(iVar2 + 7) = *(undefined *)(iVar3 + 7);
    iVar2 = FUN_8002df90(iVar2,5,0xffffffff,0xffffffff,0);
    *param_2 = iVar2;
    *(float *)(*param_2 + 8) = FLOAT_803dda94;
  }
  return;
}

