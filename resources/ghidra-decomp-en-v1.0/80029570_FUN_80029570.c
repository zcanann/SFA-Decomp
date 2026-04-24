// Function: FUN_80029570
// Entry: 80029570
// Size: 300 bytes

void FUN_80029570(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  longlong lVar6;
  char *local_38;
  undefined auStack52 [52];
  
  lVar6 = FUN_802860d8();
  iVar5 = (int)((ulonglong)lVar6 >> 0x20);
  if (lVar6 < 0) {
    iVar5 = -iVar5;
  }
  else {
    FUN_80048f48(0x2c,DAT_803dcb64,iVar5 << 1,8);
    iVar5 = (int)*DAT_803dcb64;
  }
  iVar2 = FUN_80013c10(DAT_803dcb54,iVar5,&local_38);
  if (iVar2 == 0) {
    local_38 = (char *)FUN_8002919c(iVar5);
    FUN_80028f94();
    pcVar1 = local_38;
    iVar2 = 0;
    for (iVar4 = 0; iVar4 < (int)(uint)(byte)pcVar1[0xf2]; iVar4 = iVar4 + 1) {
      uVar3 = FUN_800544a4(-(*(uint *)(*(int *)(pcVar1 + 0x20) + iVar2) | 0x8000),1);
      *(undefined4 *)(*(int *)(pcVar1 + 0x20) + iVar2) = uVar3;
      iVar2 = iVar2 + 4;
    }
    FUN_80028d70(local_38);
    FUN_80025420(local_38,iVar5,local_38 + *(int *)(local_38 + 0xc));
    FUN_80013ce8(DAT_803dcb54,(int)(short)iVar5,&local_38);
  }
  else {
    *local_38 = *local_38 + '\x01';
  }
  uVar3 = FUN_80025880(local_38,(int)lVar6,auStack52,0);
  *param_3 = uVar3;
  FUN_80286124(local_38);
  return;
}

