// Function: FUN_801871c8
// Entry: 801871c8
// Size: 196 bytes

undefined4 FUN_801871c8(int param_1)

{
  char cVar3;
  undefined4 uVar1;
  undefined2 *puVar2;
  
  cVar3 = FUN_8002e04c();
  if (cVar3 == '\0') {
    uVar1 = 0;
  }
  else {
    puVar2 = (undefined2 *)FUN_8002bdf4(0x24,0x43c);
    *puVar2 = 0x43c;
    *(undefined *)(puVar2 + 1) = 9;
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)((int)puVar2 + 7) = 8;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_1 + 0xc);
    *(float *)(puVar2 + 6) = FLOAT_803e3ae8 + *(float *)(param_1 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_1 + 0x14);
    *(undefined *)((int)puVar2 + 0x19) = 4;
    puVar2[0xd] = 0x514;
    puVar2[0xe] = 0x28;
    *(undefined *)(puVar2 + 0xc) = 0x1e;
    uVar1 = FUN_8002b5a0(param_1);
  }
  return uVar1;
}

