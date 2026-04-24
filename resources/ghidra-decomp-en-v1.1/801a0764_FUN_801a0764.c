// Function: FUN_801a0764
// Entry: 801a0764
// Size: 296 bytes

void FUN_801a0764(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  int local_70;
  float local_6c;
  float local_68;
  undefined4 local_64;
  int aiStack_60 [22];
  
  iVar3 = param_9[0x2e];
  *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) & 0x7f;
  if (((param_9[0x31] != 0) &&
      (((iVar1 = FUN_80036974((int)param_9,&local_70,(int *)0x0,(uint *)0x0), iVar1 != 0 ||
        (local_70 = *(int *)(param_9[0x15] + 0x50), local_70 != 0)) &&
       (iVar1 = FUN_8002bac4(), local_70 == iVar1)))) &&
     (bVar2 = FUN_80296434(local_70), bVar2 == 0)) {
    local_6c = *(float *)(local_70 + 0xc);
    local_68 = (float)((double)FLOAT_803e4f30 + (double)*(float *)(local_70 + 0x10));
    local_64 = *(undefined4 *)(local_70 + 0x14);
    iVar1 = FUN_802223bc((double)FLOAT_803e4f30,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,(float *)(param_9 + 3),&local_6c);
    if (iVar1 != 0) {
      if ((param_9[0x3d] == 0) &&
         (iVar1 = FUN_80064248(param_9 + 3,&local_6c,(float *)0x0,aiStack_60,param_9,4,0xffffffff,0,
                               0), iVar1 != 0)) {
        return;
      }
      *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) & 0x7f | 0x80;
    }
  }
  return;
}

