// Function: FUN_80290ee0
// Entry: 80290ee0
// Size: 300 bytes

void FUN_80290ee0(int param_1,int param_2)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  
  if (-1 < param_2) {
    if ((int)(uint)*(byte *)(param_1 + 4) <= param_2) {
      return;
    }
    iVar4 = param_1 + param_2;
    pcVar6 = (char *)(iVar4 + 5);
    uVar5 = (uint)(char)(*(char *)(iVar4 + 5) + -0x30);
    if (uVar5 == 5) {
      pcVar3 = (char *)(param_1 + (uint)*(byte *)(param_1 + 4) + 5);
      do {
        pcVar3 = pcVar3 + -1;
        if (pcVar3 <= pcVar6) break;
      } while (*pcVar3 == '0');
      if (pcVar3 == pcVar6) {
        uVar5 = *(byte *)(iVar4 + 4) & 1;
      }
      else {
        uVar5 = 1;
      }
    }
    else {
      uVar5 = ((int)(uVar5 ^ 5) >> 1) - ((uVar5 ^ 5) & uVar5) >> 0x1f;
    }
    for (; param_2 != 0; param_2 = param_2 + -1) {
      pcVar6 = pcVar6 + -1;
      cVar1 = *pcVar6 + (char)uVar5;
      cVar2 = cVar1 + -0x30;
      uVar5 = (int)cVar2 ^ 9;
      uVar5 = -((int)(((int)uVar5 >> 1) - (uVar5 & (int)cVar2)) >> 0x1f);
      if ((uVar5 == 0) && (cVar2 != '\0')) {
        *pcVar6 = cVar1;
        break;
      }
    }
    if (uVar5 != 0) {
      *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + 1;
      *(undefined *)(param_1 + 4) = 1;
      *(undefined *)(param_1 + 5) = 0x31;
      return;
    }
    if (param_2 != 0) {
      *(char *)(param_1 + 4) = (char)param_2;
      return;
    }
  }
  *(undefined2 *)(param_1 + 2) = 0;
  *(undefined *)(param_1 + 4) = 1;
  *(undefined *)(param_1 + 5) = 0x30;
  return;
}

