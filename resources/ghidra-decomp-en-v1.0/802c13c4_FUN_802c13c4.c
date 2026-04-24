// Function: FUN_802c13c4
// Entry: 802c13c4
// Size: 688 bytes

void FUN_802c13c4(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  float local_18;
  float local_14;
  float local_10;
  
  FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar4 + 0xbae) = 5;
  uVar2 = FUN_8001ffb4(0xed7);
  FUN_80137948(s_ON_CLOUD__d_80335830,uVar2);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  if (*(char *)(iVar4 + 0xbb2) == '\x02') {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_802c11bc((double)FLOAT_803db414,param_1,0xffffffff);
    *(uint *)(*(int *)(param_1 + 0x50) + 0x44) =
         *(uint *)(*(int *)(param_1 + 0x50) + 0x44) | 0x200000;
  }
  else {
    *(undefined *)(iVar4 + 0x25f) = 0;
    FUN_802c11bc((double)FLOAT_803db414,param_1,0xffffffff);
    *(uint *)(*(int *)(param_1 + 0x50) + 0x44) =
         *(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 0xffdfffff;
  }
  if ((*(char *)(iVar4 + 0xbc3) != '\0') &&
     (cVar1 = *(char *)(iVar4 + 0xbc3) - DAT_803db410, *(char *)(iVar4 + 0xbc3) = cVar1,
     cVar1 < '\0')) {
    *(undefined *)(iVar4 + 0xbc3) = 0;
  }
  if (*(char *)(iVar4 + 0xbb2) == '\x02') {
    FUN_80035e8c(param_1);
    *(byte *)(iVar4 + 0xad5) = *(byte *)(iVar4 + 0xad5) | 1;
  }
  else {
    *(byte *)(iVar4 + 0xad5) = *(byte *)(iVar4 + 0xad5) & 0xfe;
  }
  FUN_80115094(param_1,iVar4 + 0x4c4);
  FUN_80038f38(param_1,iVar4 + 0x494);
  FUN_8003b500((double)FLOAT_803e83a4,param_1,iVar4 + 0x464);
  FUN_8003b310(param_1,iVar4 + 0x464);
  if (((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(char *)(iVar4 + 0xbb2) == '\0')) {
    if ((*(byte *)(iVar4 + 0xbc0) >> 4 & 1) == 0) {
      FUN_80014b3c(0,0x100);
      if (*(char *)(iVar4 + 0xbc4) != -1) {
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar4 + 0xbc4),param_1,0xffffffff);
      }
    }
    else {
      FUN_80014b3c(0,0x100);
      iVar3 = (**(code **)(*DAT_803dcaac + 0x30))();
      if (iVar3 == 0) {
        local_18 = FLOAT_803e8418;
        local_14 = FLOAT_803e841c;
        local_10 = FLOAT_803e8420;
        (**(code **)(*DAT_803dcaac + 0x24))(&local_18,0,0,0);
      }
      (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
      *(undefined4 *)(iVar4 + 0xb04) = 0;
      *(byte *)(iVar4 + 0xbb6) = *(byte *)(iVar4 + 0xbb6) | 4;
      *(byte *)(iVar4 + 0xad5) = *(byte *)(iVar4 + 0xad5) | 1;
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar4,4);
    }
  }
  return;
}

