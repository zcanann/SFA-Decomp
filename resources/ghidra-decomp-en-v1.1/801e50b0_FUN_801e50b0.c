// Function: FUN_801e50b0
// Entry: 801e50b0
// Size: 212 bytes

undefined4 FUN_801e50b0(uint param_1,undefined4 param_2,int param_3)

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
    iVar2 = FUN_8002fb40((double)FLOAT_803e65b0,(double)FLOAT_803dc074);
    if (iVar2 != 0) {
      FUN_8000bb38(param_1,0x315);
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

