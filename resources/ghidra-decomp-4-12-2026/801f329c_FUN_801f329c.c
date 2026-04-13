// Function: FUN_801f329c
// Entry: 801f329c
// Size: 344 bytes

void FUN_801f329c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  float *pfVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  uVar3 = 0xb;
  uVar4 = (uint)((*(byte *)(iVar6 + 0x22) & 0x80) != 0);
  pfVar5 = (float *)(iVar6 + 0x10);
  cVar1 = FUN_8003549c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       &DAT_803294d8,0xb,uVar4,pfVar5,in_r8,in_r9,in_r10);
  if (cVar1 == '\0') {
    *(byte *)(iVar6 + 0x22) = *(byte *)(iVar6 + 0x22) & 0x7f;
    uVar7 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0x56));
    uVar2 = (undefined4)uVar7;
    switch((uint)((ulonglong)uVar7 >> 0x20) & 0xff) {
    case 1:
      FUN_801f2e1c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                   uVar2,uVar3,uVar4,pfVar5,in_r8,in_r9,in_r10);
      break;
    case 2:
      FUN_801f28c8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                   ,uVar3,uVar4,pfVar5,in_r8,in_r9,in_r10);
      break;
    case 4:
      *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
      if (param_9[0x50] != 2) {
        FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,2,0,uVar4,pfVar5,in_r8,in_r9,in_r10);
      }
      FUN_8002fb40((double)FLOAT_803e6a34,
                   (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e6a38
                                  ));
      break;
    case 6:
      FUN_801f270c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                   uVar2,uVar3,uVar4,pfVar5,in_r8,in_r9,in_r10);
    }
  }
  else {
    *(byte *)(iVar6 + 0x22) = *(byte *)(iVar6 + 0x22) | 0x80;
  }
  return;
}

