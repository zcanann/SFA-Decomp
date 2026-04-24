// Function: FUN_801e4ac0
// Entry: 801e4ac0
// Size: 212 bytes

undefined4 FUN_801e4ac0(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(param_3 + iVar3 + 0x81);
    if (cVar1 == '\x01') {
      *(undefined *)(iVar2 + 4) = 1;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar2 + 4) = 2;
    }
  }
  *(undefined2 *)(param_3 + 0x6e) = 0xfffc;
  if (*(short *)(param_1 + 0xb4) != -1) {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
    iVar2 = FUN_8002fa48((double)FLOAT_803e5918,(double)FLOAT_803db414,param_1,0);
    if (iVar2 != 0) {
      FUN_8000bb18(param_1,0x315);
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

