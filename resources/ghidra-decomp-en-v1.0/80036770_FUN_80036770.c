// Function: FUN_80036770
// Entry: 80036770
// Size: 268 bytes

int FUN_80036770(int param_1,undefined4 *param_2,int *param_3,uint *param_4,undefined4 *param_5,
                undefined4 *param_6,undefined4 *param_7)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  char cVar6;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    iVar2 = (int)*(char *)(iVar3 + 0x71);
    if (iVar2 != 0) {
      cVar6 = '\x7f';
      cVar5 = -1;
      iVar4 = 0;
      if (0 < iVar2) {
        do {
          cVar1 = *(char *)(iVar3 + iVar4 + 0x75);
          if (cVar1 < cVar6) {
            cVar5 = (char)iVar4;
            cVar6 = cVar1;
          }
          iVar4 = iVar4 + 1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
      if (cVar5 != -1) {
        if (param_2 != (undefined4 *)0x0) {
          *param_2 = *(undefined4 *)(iVar3 + cVar5 * 4 + 0x7c);
        }
        if (param_3 != (int *)0x0) {
          *param_3 = (int)*(char *)(iVar3 + cVar5 + 0x72);
        }
        if (param_4 != (uint *)0x0) {
          *param_4 = (uint)*(byte *)(iVar3 + cVar5 + 0x78);
        }
        if (param_5 != (undefined4 *)0x0) {
          iVar3 = iVar3 + cVar5 * 4;
          *param_5 = *(undefined4 *)(iVar3 + 0x88);
          *param_6 = *(undefined4 *)(iVar3 + 0x94);
          *param_7 = *(undefined4 *)(iVar3 + 0xa0);
        }
        return (int)cVar6;
      }
    }
  }
  return 0;
}

