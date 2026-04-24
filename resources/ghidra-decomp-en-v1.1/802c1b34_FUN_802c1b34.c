// Function: FUN_802c1b34
// Entry: 802c1b34
// Size: 688 bytes

void FUN_802c1b34(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  char cVar1;
  int iVar2;
  int iVar3;
  float local_18;
  float local_14;
  float local_10;
  
  FUN_8002bac4();
  iVar3 = *(int *)(param_9 + 0x5c);
  *(undefined2 *)(iVar3 + 0xbae) = 5;
  FUN_80020078(0xed7);
  FUN_80137cd0();
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  if (*(char *)(iVar3 + 0xbb2) == '\x02') {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    FUN_802c192c((double)FLOAT_803dc074,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,-1);
    *(uint *)(*(int *)(param_9 + 0x28) + 0x44) =
         *(uint *)(*(int *)(param_9 + 0x28) + 0x44) | 0x200000;
  }
  else {
    *(undefined *)(iVar3 + 0x25f) = 0;
    FUN_802c192c((double)FLOAT_803dc074,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,-1);
    *(uint *)(*(int *)(param_9 + 0x28) + 0x44) =
         *(uint *)(*(int *)(param_9 + 0x28) + 0x44) & 0xffdfffff;
  }
  if ((*(char *)(iVar3 + 0xbc3) != '\0') &&
     (cVar1 = *(char *)(iVar3 + 0xbc3) - DAT_803dc070, *(char *)(iVar3 + 0xbc3) = cVar1,
     cVar1 < '\0')) {
    *(undefined *)(iVar3 + 0xbc3) = 0;
  }
  if (*(char *)(iVar3 + 0xbb2) == '\x02') {
    FUN_80035f84((int)param_9);
    *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) | 1;
  }
  else {
    *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) & 0xfe;
  }
  FUN_80115330();
  FUN_80039030((int)param_9,(char *)(iVar3 + 0x494));
  FUN_8003b5f8((short *)param_9,(char *)(iVar3 + 0x464));
  FUN_8003b408((int)param_9,iVar3 + 0x464);
  if (((*(byte *)((int)param_9 + 0xaf) & 1) != 0) && (*(char *)(iVar3 + 0xbb2) == '\0')) {
    if ((*(byte *)(iVar3 + 0xbc0) >> 4 & 1) == 0) {
      FUN_80014b68(0,0x100);
      if (*(char *)(iVar3 + 0xbc4) != -1) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0xbc4),param_9,0xffffffff);
      }
    }
    else {
      FUN_80014b68(0,0x100);
      iVar2 = (**(code **)(*DAT_803dd72c + 0x30))();
      if (iVar2 == 0) {
        local_18 = FLOAT_803e90b0;
        local_14 = FLOAT_803e90b4;
        local_10 = FLOAT_803e90b8;
        (**(code **)(*DAT_803dd72c + 0x24))(&local_18,0,0,0);
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_9,0xffffffff);
      *(undefined4 *)(iVar3 + 0xb04) = 0;
      *(byte *)(iVar3 + 0xbb6) = *(byte *)(iVar3 + 0xbb6) | 4;
      *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) | 1;
      (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar3,4);
    }
  }
  return;
}

