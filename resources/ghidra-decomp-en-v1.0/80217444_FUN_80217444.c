// Function: FUN_80217444
// Entry: 80217444
// Size: 492 bytes

void FUN_80217444(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_38;
  undefined local_34 [3];
  char cStack49;
  undefined auStack48 [4];
  undefined auStack44 [4];
  undefined auStack40 [40];
  
  iVar1 = FUN_802860dc();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar4 = *(int *)(iVar1 + 0x4c);
  if ((-1 < (char)*(byte *)(iVar5 + 0x1a8)) && ((*(byte *)(iVar5 + 0x1a8) >> 4 & 1) == 0)) {
    iVar2 = FUN_80036770(iVar1,&local_38,0,local_34,auStack48,auStack44,auStack40);
    if ((*(byte *)(iVar5 + 0x1a8) >> 1 & 1) == 0) {
      if ((((iVar2 - 0xeU < 2) || (iVar2 == 5)) && (*(int *)(iVar5 + 0xc) != local_38)) &&
         ((int)*(short *)(local_38 + 0x46) != *(int *)(iVar5 + 0x19c))) {
        *(int *)(iVar5 + 0xc) = local_38;
        *(char *)(iVar5 + 0x1a6) = *(char *)(iVar5 + 0x1a6) - cStack49;
        FUN_80221e94((double)FLOAT_803e68f0,iVar1,auStack48);
        FUN_8009a8c8((double)FLOAT_803e68f4,iVar1);
        FUN_8000bb18(iVar1,0x3cc);
        if (*(char *)(iVar5 + 0x1a6) < '\x01') {
          iVar3 = FUN_8002b9ac();
          FUN_8000bb18(iVar1,0x4b6);
          FUN_8009ab70((double)FLOAT_803e68f8,iVar1,0,1,1,1,0,1,0);
          *(byte *)(iVar5 + 0x1a8) = *(byte *)(iVar5 + 0x1a8) & 0x7f | 0x80;
          FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
          if (iVar3 != 0) {
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x34))(iVar3,0,0);
          }
          *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
        }
      }
    }
    else if (((iVar2 != 0) && ((int)*(short *)(local_38 + 0x46) != *(int *)(iVar5 + 0x19c))) &&
            (*(int *)(iVar5 + 400) != 0)) {
      FUN_80170380(*(int *)(iVar5 + 400),6);
    }
    if (iVar2 == 0) {
      *(undefined4 *)(iVar5 + 0xc) = 0;
    }
    else {
      *(int *)(iVar5 + 0xc) = local_38;
    }
  }
  FUN_80286128();
  return;
}

