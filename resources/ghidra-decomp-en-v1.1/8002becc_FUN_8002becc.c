// Function: FUN_8002becc
// Entry: 8002becc
// Size: 148 bytes

undefined2 * FUN_8002becc(uint param_1,undefined2 param_2)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)FUN_80023d8c(param_1,0xe);
  FUN_800033a8((int)puVar1,0,param_1);
  *(undefined4 *)(puVar1 + 10) = 0xffffffff;
  *(undefined *)(puVar1 + 3) = 100;
  *(undefined *)((int)puVar1 + 7) = 0x96;
  *(undefined *)(puVar1 + 2) = 8;
  *(undefined *)((int)puVar1 + 5) = 4;
  *puVar1 = param_2;
  *(char *)(puVar1 + 1) = (char)param_1;
  return puVar1;
}

