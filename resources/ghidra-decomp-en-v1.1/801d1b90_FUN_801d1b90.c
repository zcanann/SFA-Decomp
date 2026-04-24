// Function: FUN_801d1b90
// Entry: 801d1b90
// Size: 332 bytes

void FUN_801d1b90(int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *local_70;
  int aiStack_6c [20];
  char local_1c;
  
  iVar5 = param_1[0x2e];
  iVar4 = param_1[0x13];
  if (((*(ushort *)(param_1 + 0x2c) & 0x1000) == 0) &&
     (((*(byte *)(iVar5 + 0x137) & 8) != 0 || ((*(ushort *)(param_1[0x15] + 0x60) & 8) != 0)))) {
    iVar1 = FUN_80065fcc((double)(float)param_1[3],(double)(float)param_1[4],
                         (double)(float)param_1[5],param_1,&local_70,0,0);
    iVar3 = 0;
    puVar2 = local_70;
    if (0 < iVar1) {
      do {
        if (*(float *)*puVar2 < FLOAT_803e5f2c + (float)param_1[4]) {
          param_1[4] = *(int *)local_70[iVar3];
          break;
        }
        puVar2 = puVar2 + 1;
        iVar3 = iVar3 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar1 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x2,aiStack_6c,param_1,8,0xffffffff,
                         0xff,0x14);
    if (((*(char *)(iVar4 + 0x18) == '\x04') && (iVar1 != 0)) && (local_1c == '\r')) {
      *(byte *)(iVar5 + 0x137) = *(byte *)(iVar5 + 0x137) | 4;
    }
  }
  return;
}

