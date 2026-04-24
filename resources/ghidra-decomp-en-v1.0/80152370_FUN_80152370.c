// Function: FUN_80152370
// Entry: 80152370
// Size: 208 bytes

undefined4 FUN_80152370(int param_1,undefined4 param_2)

{
  char cVar3;
  undefined4 uVar1;
  undefined2 *puVar2;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  FUN_8002b9ec();
  cVar3 = FUN_8002e04c();
  if (cVar3 == '\0') {
    uVar1 = 0;
  }
  else {
    puVar2 = (undefined2 *)FUN_8002bdf4(0x24,param_2);
    *puVar2 = (short)param_2;
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar4 + 7);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)((int)puVar2 + 0x19) = 0;
    puVar2[0x10] = 0x95;
    uVar1 = FUN_8002df90(puVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                         *(undefined4 *)(param_1 + 0x30));
  }
  return uVar1;
}

