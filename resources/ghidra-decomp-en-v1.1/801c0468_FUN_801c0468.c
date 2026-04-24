// Function: FUN_801c0468
// Entry: 801c0468
// Size: 312 bytes

void FUN_801c0468(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int *piVar1;
  int iVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar3;
  double dVar4;
  
  puVar3 = *(undefined2 **)(param_9 + 0xb8);
  piVar1 = FUN_8001f58c(param_9,'\x01');
  *(int **)(puVar3 + 2) = piVar1;
  if (*(int *)(puVar3 + 2) != 0) {
    FUN_8001dbf0(*(int *)(puVar3 + 2),2);
    FUN_8001dbb4(*(int *)(puVar3 + 2),0,0xff,0,0);
    FUN_8001dadc(*(int *)(puVar3 + 2),0,0xff,0,0);
    dVar4 = (double)FLOAT_803e5a0c;
    FUN_8001dcfc((double)FLOAT_803e5a08,dVar4,*(int *)(puVar3 + 2));
    FUN_8001dc18(*(int *)(puVar3 + 2),1);
    FUN_8001dc30((double)FLOAT_803e5a10,*(int *)(puVar3 + 2),'\x01');
    FUN_8001de04(*(int *)(puVar3 + 2),1);
    FUN_8001d7f4((double)FLOAT_803e5a14,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(puVar3 + 2),0,0,0xff,0,0x7f,in_r9,in_r10);
    FUN_8001d7d8((double)FLOAT_803e5a18,*(int *)(puVar3 + 2));
  }
  *(undefined4 *)(param_9 + 0xf4) = 0xb4;
  FUN_80035eec(param_9,0,0,0);
  FUN_80035a6c(param_9,0);
  *puVar3 = 0;
  puVar3[1] = 0;
  FUN_80036018(param_9);
  iVar2 = FUN_8002b660(param_9);
  FUN_800285f0(iVar2,FUN_80028590);
  return;
}

