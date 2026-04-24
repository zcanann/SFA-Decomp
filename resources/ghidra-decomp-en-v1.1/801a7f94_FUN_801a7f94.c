// Function: FUN_801a7f94
// Entry: 801a7f94
// Size: 304 bytes

void FUN_801a7f94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)

{
  int iVar1;
  int iVar2;
  undefined4 uStack_60;
  int aiStack_5c [21];
  
  iVar2 = param_9[0x2e];
  iVar1 = FUN_80036974((int)param_9,&uStack_60,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0) {
    iVar1 = FUN_80064248(param_9 + 0x20,param_9 + 3,(float *)0x1,aiStack_5c,param_9,1,0xffffffff,
                         0xff,0);
  }
  if ((iVar1 != 0) ||
     (((*(char *)(param_9[0x15] + 0xad) != '\0' && ((*(ushort *)(iVar2 + 0x24) & 0x40) != 0)) ||
      ((*(ushort *)(iVar2 + 0x24) & 0x100) != 0)))) {
    param_9[4] = (int)((float)param_9[4] + FLOAT_803e51e8);
    FUN_8009adfc((double)FLOAT_803e51ec,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,1,0,0,0,1,0);
    *(ushort *)(iVar2 + 0x24) = *(ushort *)(iVar2 + 0x24) | 0x200;
    *(float *)(iVar2 + 0x14) = FLOAT_803e51f0;
    *(undefined *)((int)param_9 + 0x36) = 0;
    param_9[3] = *(int *)(iVar2 + 0x18);
    param_9[4] = *(int *)(iVar2 + 0x1c);
    param_9[5] = *(int *)(iVar2 + 0x20);
    FUN_800e85f4((int)param_9);
  }
  return;
}

