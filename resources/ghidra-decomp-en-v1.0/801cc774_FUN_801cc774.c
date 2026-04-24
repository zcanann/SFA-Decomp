// Function: FUN_801cc774
// Entry: 801cc774
// Size: 476 bytes

void FUN_801cc774(int param_1)

{
  int iVar1;
  int *piVar2;
  char cVar4;
  undefined2 *puVar3;
  int iVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(param_1 + 0xf8) != 0) && (iVar1 = FUN_8001ffb4(0x1d4), iVar1 != 0)) {
    *(undefined4 *)(param_1 + 0xf8) = 0;
  }
  if ((*(int *)(param_1 + 0xf8) == 0) && (iVar1 = FUN_8001ffb4(0x1d3), iVar1 != 0)) {
    piVar2 = (int *)FUN_80013ec8(0x82,1);
    (**(code **)(*piVar2 + 4))(param_1,0,0,1,0xffffffff,0);
    (**(code **)(*piVar2 + 4))(param_1,1,0,1,0xffffffff,0);
    FUN_8000bb18(0,0xaf);
    FUN_80013e2c(piVar2);
    *(undefined2 *)(iVar5 + 6) = 1;
    *(undefined4 *)(param_1 + 0xf8) = 1;
  }
  if (*(short *)(iVar5 + 6) != 0) {
    *(ushort *)(iVar5 + 4) = *(short *)(iVar5 + 4) - *(short *)(iVar5 + 6) * (ushort)DAT_803db410;
  }
  if (((*(short *)(iVar5 + 4) < 1) && (*(char *)(iVar6 + 0x1f) == '\0')) &&
     (cVar4 = FUN_8002e04c(), cVar4 != '\0')) {
    puVar3 = (undefined2 *)FUN_8002bdf4(0x18,0x248);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar6 + 8);
    *(float *)(puVar3 + 6) = FLOAT_803e51b4 + *(float *)(iVar6 + 0xc);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar6 + 0x10);
    *puVar3 = 0x248;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar6 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar6 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar6 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar6 + 7);
    FUN_8002df90(puVar3,5,(int)*(char *)(param_1 + 0xac),0xffffffff,*(undefined4 *)(param_1 + 0x30))
    ;
    *(undefined2 *)(iVar5 + 4) = 100;
    *(undefined2 *)(iVar5 + 6) = 0;
  }
  return;
}

