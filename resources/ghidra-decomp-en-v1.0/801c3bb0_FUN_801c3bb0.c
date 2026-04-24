// Function: FUN_801c3bb0
// Entry: 801c3bb0
// Size: 584 bytes

void FUN_801c3bb0(undefined2 *param_1)

{
  int iVar1;
  int *piVar2;
  char cVar3;
  short *psVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x26);
  psVar4 = *(short **)(param_1 + 0x5c);
  iVar1 = FUN_8001ffb4(0x589);
  if (iVar1 == 0) {
    if ((*(int *)(param_1 + 0x7c) == 0) &&
       (iVar1 = FUN_8001ffb4(*(char *)(iVar5 + 0x1f) + 0xf6), iVar1 != 0)) {
      piVar2 = (int *)FUN_80013ec8(0x82,1);
      (**(code **)(*piVar2 + 4))(param_1,0,0,1,0xffffffff,0);
      (**(code **)(*piVar2 + 4))(param_1,1,0,1,0xffffffff,0);
      FUN_8000bb18(param_1,0xaf);
      FUN_80013e2c(piVar2);
      psVar4[1] = 1;
      *(undefined4 *)(param_1 + 0x7c) = 1;
    }
    if (psVar4[1] != 0) {
      *psVar4 = *psVar4 - psVar4[1] * (short)(int)FLOAT_803db414;
    }
    cVar3 = FUN_8002e04c();
    if ((cVar3 != '\0') && (*psVar4 < 1)) {
      iVar1 = FUN_8002bdf4(0x38,0x11);
      *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar5 + 0x10);
      *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar5 + 0x14);
      *(undefined *)(iVar1 + 4) = *(undefined *)(iVar5 + 4);
      *(undefined *)(iVar1 + 5) = *(undefined *)(iVar5 + 5);
      *(undefined *)(iVar1 + 6) = *(undefined *)(iVar5 + 6);
      *(undefined *)(iVar1 + 7) = *(undefined *)(iVar5 + 7);
      *(undefined *)(iVar1 + 0x27) = 3;
      *(undefined2 *)(iVar1 + 0x18) = 0x1e7;
      *(undefined2 *)(iVar1 + 0x30) = 0xffff;
      *(undefined2 *)(iVar1 + 0x1a) = 0xffff;
      *(undefined2 *)(iVar1 + 0x1c) = 0xffff;
      *(char *)(iVar1 + 0x2a) = (char)((ushort)*param_1 >> 8);
      *(undefined *)(iVar1 + 0x2b) = 2;
      iVar5 = FUN_8001ffb4(0xfc);
      if (iVar5 == 0) {
        *(undefined2 *)(iVar1 + 0x22) = 0xffff;
      }
      else {
        *(undefined2 *)(iVar1 + 0x22) = 0x49;
      }
      *(undefined *)(iVar1 + 0x29) = 0xff;
      *(undefined *)(iVar1 + 0x2e) = 0xff;
      *(undefined2 *)(iVar1 + 0x34) = 0xffff;
      FUN_8002df90(iVar1,5,(int)*(char *)(param_1 + 0x56),0xffffffff,*(undefined4 *)(param_1 + 0x18)
                  );
      *psVar4 = 100;
      psVar4[1] = 0;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x7c) = 0;
  }
  return;
}

