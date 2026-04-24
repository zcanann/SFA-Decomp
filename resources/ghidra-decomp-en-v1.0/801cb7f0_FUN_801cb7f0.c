// Function: FUN_801cb7f0
// Entry: 801cb7f0
// Size: 612 bytes

void FUN_801cb7f0(undefined2 *param_1)

{
  int iVar1;
  int *piVar2;
  char cVar4;
  int iVar3;
  short *psVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0x26);
  psVar5 = *(short **)(param_1 + 0x5c);
  iVar1 = FUN_8001ffb4(0x5b9);
  if (iVar1 == 0) {
    if ((*(int *)(param_1 + 0x7c) == 0) &&
       (iVar1 = FUN_8001ffb4(*(char *)(iVar6 + 0x1f) + 0x1cd), iVar1 != 0)) {
      piVar2 = (int *)FUN_80013ec8(0x82,1);
      (**(code **)(*piVar2 + 4))(param_1,0,0,1,0xffffffff,0);
      (**(code **)(*piVar2 + 4))(param_1,1,0,1,0xffffffff,0);
      FUN_8000bb18(param_1,0xaf);
      FUN_80013e2c(piVar2);
      psVar5[1] = 1;
      *(undefined4 *)(param_1 + 0x7c) = 1;
    }
    if (psVar5[1] != 0) {
      *psVar5 = *psVar5 - psVar5[1] * (ushort)DAT_803db410;
    }
    if ((*psVar5 < 1) && (cVar4 = FUN_8002e04c(), cVar4 != '\0')) {
      iVar1 = FUN_8002bdf4(0x38,0x2d0);
      *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar6 + 0x10);
      *(undefined *)(iVar1 + 4) = *(undefined *)(iVar6 + 4);
      *(undefined *)(iVar1 + 5) = *(undefined *)(iVar6 + 5);
      *(undefined *)(iVar1 + 6) = *(undefined *)(iVar6 + 6);
      *(undefined *)(iVar1 + 7) = *(undefined *)(iVar6 + 7);
      *(undefined *)(iVar1 + 0x27) = 1;
      *(undefined2 *)(iVar1 + 0x18) = 0x1e7;
      *(undefined2 *)(iVar1 + 0x30) = 0xffff;
      *(char *)(iVar1 + 0x2a) = (char)((ushort)*param_1 >> 8);
      *(undefined *)(iVar1 + 0x2b) = 2;
      iVar3 = FUN_8001ffb4(0x1ce);
      if (iVar3 == 0) {
        *(undefined2 *)(iVar1 + 0x22) = 0xffff;
      }
      else {
        *(undefined2 *)(iVar1 + 0x22) = 0x49;
      }
      *(undefined *)(iVar1 + 0x29) = 0xff;
      *(undefined *)(iVar1 + 0x2e) = 0xff;
      *(undefined *)(iVar1 + 0x32) = *(undefined *)(iVar6 + 0x1f);
      iVar1 = FUN_8002df90(iVar1,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                           *(undefined4 *)(param_1 + 0x18));
      if ((iVar1 != 0) && (*(int *)(iVar1 + 0xb8) != 0)) {
        *(undefined *)(*(int *)(iVar1 + 0xb8) + 0x404) = 0x20;
      }
      *psVar5 = 100;
      psVar5[1] = 0;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x7c) = 0;
    *psVar5 = 100;
    psVar5[1] = 0;
    *(undefined *)((int)param_1 + 0x37) = 0xff;
    *(undefined *)(param_1 + 0x1b) = 0xff;
  }
  return;
}

