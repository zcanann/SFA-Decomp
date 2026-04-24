// Function: FUN_801c6e54
// Entry: 801c6e54
// Size: 568 bytes

void FUN_801c6e54(undefined2 *param_1)

{
  int iVar1;
  int *piVar2;
  char cVar4;
  undefined2 *puVar3;
  short *psVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0x26);
  psVar5 = *(short **)(param_1 + 0x5c);
  if ((*(int *)(param_1 + 0x7c) == 0) && (iVar1 = FUN_8001ffb4((int)psVar5[2]), iVar1 != 0)) {
    piVar2 = (int *)FUN_80013ec8(0x82,1);
    (**(code **)(*piVar2 + 4))(param_1,0,0,1,0xffffffff,0);
    (**(code **)(*piVar2 + 4))(param_1,1,0,1,0xffffffff,0);
    FUN_8000bb18(param_1,0x16d);
    FUN_80013e2c(piVar2);
    psVar5[1] = 1;
    *(undefined4 *)(param_1 + 0x7c) = 1;
  }
  if (psVar5[1] != 0) {
    *psVar5 = *psVar5 - psVar5[1] * (ushort)DAT_803db410;
  }
  cVar4 = FUN_8002e04c();
  if ((cVar4 != '\0') && (*psVar5 < 1)) {
    puVar3 = (undefined2 *)FUN_80023cc8(0x38,0xe,0);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar6 + 8);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar6 + 0x10);
    *puVar3 = 0x11;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar6 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar6 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar6 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar6 + 7);
    *(undefined *)((int)puVar3 + 0x27) = 3;
    *(undefined *)(puVar3 + 0x14) = 0;
    puVar3[0xc] = psVar5[2] + (short)*(char *)(iVar6 + 0x1f);
    puVar3[0x18] = 0xffff;
    *(char *)(puVar3 + 0x15) = (char)((ushort)*param_1 >> 8);
    *(undefined *)((int)puVar3 + 0x2b) = 2;
    puVar3[0x10] = 0;
    puVar3[0xf] = 0;
    puVar3[0x11] = 0xffff;
    *(undefined *)((int)puVar3 + 0x29) = 0xff;
    *(undefined *)(puVar3 + 0x17) = 0xff;
    puVar3[0x12] = 0;
    puVar3[0x16] = 0;
    puVar3[0x1a] = 0xffff;
    puVar3[0xd] = 0;
    *(char *)(puVar3 + 0x19) = (char)psVar5[4];
    iVar6 = FUN_8002df90(puVar3,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                         *(undefined4 *)(param_1 + 0x18));
    if (iVar6 != 0) {
      *(undefined *)(*(int *)(iVar6 + 0xb8) + 0x404) = 0x20;
    }
    *psVar5 = 100;
    psVar5[1] = 0;
  }
  return;
}

